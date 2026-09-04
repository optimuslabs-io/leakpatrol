// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// execCLI drives run() in-process. It clears every environment variable that
// could make a test reach a REAL Coder deployment or database: a developer with
// a live `coder login` would otherwise have the deploy tier quietly succeed (or
// hang on the network) during `go test`.
func execCLI(t *testing.T, stdin io.Reader, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	for _, k := range []string{
		"CODER_URL", "CODER_SESSION_TOKEN", "CODER_PG_CONNECTION_URL",
		"LEAKPATROL_OFFLINE", "NO_COLOR",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	// Point the coder CLI's config discovery at an empty dir so Discover cannot
	// pick up a real ~/.config/coderv2/session.
	t.Setenv("CODER_CONFIG_DIR", t.TempDir())

	var out, errb bytes.Buffer
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	code = run(args, &out, &errb, stdin)
	return out.String(), errb.String(), code
}

// The IR contract that matters most: a command that could not check anything
// must be a tool error, never a report. `leakpatrol deploy && page-nobody`
// has to page somebody.
func TestCommandsThatCannotRunAreToolErrorsNotCleanReports(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string // substring required on stderr
	}{
		{"deploy without server or token", []string{"deploy"}, "cannot run"},
		{"db without a dsn", []string{"db"}, "cannot run"},
		{"image with no arguments", []string{"image"}, "cannot run"},
		{"logs with no arguments", []string{"logs"}, "cannot run"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, stderr, code := execCLI(t, nil, c.args...)
			if code != 1 {
				t.Errorf("exit = %d, want 1", code)
			}
			if !strings.Contains(stderr, c.want) {
				t.Errorf("stderr missing %q:\n%s", c.want, stderr)
			}
			if strings.Contains(stdout, "VERDICT") {
				t.Errorf("a command that could not run must not print a verdict:\n%s", stdout)
			}
		})
	}
}

func TestNoArgumentsPrintsUsageAndFails(t *testing.T) {
	stdout, stderr, code := execCLI(t, nil)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, "USAGE") {
		t.Errorf("usage should go to stderr:\n%s", stderr)
	}
	if strings.Contains(stdout, "VERDICT") {
		t.Error("no arguments must not produce a verdict")
	}
}

// Go's flag package stops at the first non-flag, so a flag AFTER a file silently
// became a scan target and never parsed. Both halves of that bug are contracts now.
func TestFlagsAfterFilesAreRejected(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "fw.log")
	if err := os.WriteFile(logFile, []byte("nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"logs", logFile, "--json"},
		{"fs", dir, "--quiet"},
		{"image", filepath.Join(dir, "x.tar"), "--no-animation", "--color", "never"},
	} {
		stdout, stderr, code := execCLI(t, nil, args...)
		if code != 1 || !strings.Contains(stderr, "flags go BEFORE") {
			t.Errorf("%v: exit=%d stderr=%q", args, code, stderr)
		}
		if strings.Contains(stdout, "VERDICT") {
			t.Errorf("%v: must not print a verdict", args)
		}
	}
}

// A mistyped tar must stop, not fall through to `docker save <typo>` and get
// counted as a scanned image under an INDETERMINATE verdict.
func TestMissingImageAndLogPathsAreToolErrors(t *testing.T) {
	// A fake docker that would "succeed" if the tier ever reached for it.
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	stdout, stderr, code := execCLI(t, nil, "image", "/tmp/leakpatrol-no-such.tar")
	if code != 1 || !strings.Contains(stderr, "no such file") {
		t.Errorf("image: exit=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stdout, "VERDICT") {
		t.Error("a missing tar must not produce a verdict")
	}

	stdout, stderr, code = execCLI(t, nil, "logs", "/tmp/leakpatrol-no-such.log")
	if code != 1 || !strings.Contains(stderr, "no such file") {
		t.Errorf("logs: exit=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stdout, "VERDICT") {
		t.Error("a missing log must not produce a verdict")
	}
}

// `version` is the TOOL's version plus the coder CLI check -- never a scan-shaped
// CLEAN, which is how it was misread before the tier was renamed coder-version.
func TestVersionCommandsPrintIdentityNotAVerdict(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		stdout, _, code := execCLI(t, nil, args...)
		if code != 0 {
			t.Errorf("%v: exit = %d, want 0", args, code)
		}
		if !strings.HasPrefix(stdout, "leakpatrol ") {
			t.Errorf("%v: stdout should start with the tool name:\n%s", args, stdout)
		}
		if strings.Contains(stdout, "VERDICT") {
			t.Errorf("%v: must not print a verdict:\n%s", args, stdout)
		}
		if !strings.Contains(stdout, "Civilizations") {
			t.Errorf("%v: attribution missing:\n%s", args, stdout)
		}
	}
}

func TestIocsEmitsTheAdvisorySet(t *testing.T) {
	stdout, _, code := execCLI(t, nil, "iocs")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	var set struct {
		Advisory string `json:"advisory"`
		Window   struct {
			Start string `json:"start"`
		} `json:"window"`
		Payloads  []map[string]string `json:"payloads"`
		CuratedBy string              `json:"curated_by"`
	}
	if err := json.Unmarshal([]byte(stdout), &set); err != nil {
		t.Fatalf("iocs must emit valid JSON: %v\n%s", err, stdout)
	}
	if set.Advisory != "GHSA-vx42-ghc9-gw65" {
		t.Errorf("advisory = %q", set.Advisory)
	}
	if len(set.Payloads) != 6 {
		t.Errorf("advisory lists 6 payload hashes, got %d", len(set.Payloads))
	}
	if !strings.HasPrefix(set.Window.Start, "2026-08-31") {
		t.Errorf("window start = %q", set.Window.Start)
	}
	if !strings.Contains(set.CuratedBy, "Civilizations") {
		t.Errorf("curated_by = %q", set.CuratedBy)
	}
}

// `all --offline` on an empty tree: a real report, JSON-only on stdout, and
// INDETERMINATE because the deployment itself was never asked.
func TestAllOfflineJSONIsCleanOnStdoutAndDegraded(t *testing.T) {
	empty := t.TempDir()
	stdout, stderr, code := execCLI(t, nil,
		"all", "--offline", "--json", "--no-animation", "--color", "never",
		"--roots", empty, "--home", empty)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (a report was produced)\nstderr: %s", code, stderr)
	}
	var rep struct {
		Verdict  string `json:"verdict"`
		Degraded bool   `json:"degraded"`
		Tool     struct {
			Author string `json:"author"`
		} `json:"tool"`
		Tiers []struct {
			Name        string `json:"name"`
			Status      string `json:"status"`
			MaterialGap bool   `json:"material_gap"`
		} `json:"tiers"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout must be JSON only (no progress leakage): %v\n%s", err, stdout)
	}
	if rep.Verdict != "INDETERMINATE" || !rep.Degraded {
		t.Errorf("offline all must be a degraded INDETERMINATE, got %s degraded=%v", rep.Verdict, rep.Degraded)
	}
	if !strings.Contains(rep.Tool.Author, "Civilizations") {
		t.Errorf("tool.author = %q", rep.Tool.Author)
	}
	gap := false
	for _, tr := range rep.Tiers {
		if tr.Name == "deploy" && tr.Status == "skipped" && tr.MaterialGap {
			gap = true
		}
	}
	if !gap {
		t.Errorf("deploy must be recorded as a material gap: %+v", rep.Tiers)
	}
	if json.Valid([]byte(stderr)) && strings.TrimSpace(stderr) != "" {
		t.Error("stderr must carry progress, not JSON")
	}
	if strings.Contains(stderr, "\x1b[") {
		t.Error("--color never must emit no escape codes on stderr")
	}
}

// A single tier that RAN and found nothing is a legitimate CLEAN -- the tool must
// still be able to say so, or operators learn to ignore every verdict.
func TestSingleTierThatRanAndFoundNothingIsClean(t *testing.T) {
	empty := t.TempDir()
	stdout, _, code := execCLI(t, nil, "fs", "--no-animation", "--color", "never", "--home", empty, empty)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.HasPrefix(stdout, "VERDICT: CLEAN") {
		t.Errorf("an empty tree scanned by a tier that ran is CLEAN:\n%s", stdout)
	}
	for _, unwanted := range []string{"ROTATE", "REMEDIATE"} {
		if strings.Contains(stdout, unwanted) {
			t.Errorf("clean report must not contain %s:\n%s", unwanted, stdout)
		}
	}
}

func TestPreflightJSONReportsTokenPresenceNotTheToken(t *testing.T) {
	t.Setenv("CODER_SESSION_TOKEN", "super-secret-session-token")
	var out, errb bytes.Buffer
	t.Setenv("CODER_CONFIG_DIR", t.TempDir())
	code := run([]string{"preflight", "--json"}, &out, &errb, strings.NewReader(""))
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	stdout := out.String()
	var pf struct {
		TokenPresent bool   `json:"token_present"`
		DSNPresent   bool   `json:"dsn_present"`
		FSScope      string `json:"fs_scope"`
		Tiers        []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"tiers"`
	}
	if err := json.Unmarshal([]byte(stdout), &pf); err != nil {
		t.Fatalf("preflight --json must be JSON: %v\n%s", err, stdout)
	}
	if !pf.TokenPresent {
		t.Error("token_present should be true when CODER_SESSION_TOKEN is set")
	}
	if strings.Contains(stdout, "super-secret-session-token") {
		t.Error("preflight must report token PRESENCE, never the token itself")
	}
	if !strings.Contains(pf.FSScope, "THIS machine") {
		t.Errorf("fs_scope must not imply provisioner coverage: %q", pf.FSScope)
	}
	if len(pf.Tiers) == 0 {
		t.Error("preflight must list tiers")
	}
}

func TestDBPrintOnlyEmitsQueriesAndPurgeSeparately(t *testing.T) {
	stdout, _, code := execCLI(t, nil, "db", "--print-only")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{"01_affected_template_versions.sql", "cached_module_files", "data.external.telemetry"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--print-only missing %q", want)
		}
	}
	if strings.Contains(stdout, "DELETE FROM files") {
		t.Error("--print-only must not include the destructive purge script")
	}

	stdout, _, code = execCLI(t, nil, "db", "--purge")
	if code != 0 {
		t.Fatalf("--purge exit = %d", code)
	}
	if !strings.Contains(stdout, "DELETE FROM files") || !strings.Contains(stdout, "COMMIT;") {
		t.Errorf("--purge must print the transaction:\n%s", stdout)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	stdout, stderr, code := execCLI(t, nil, "scan-everything")
	if code != 1 || !strings.Contains(stderr, "unknown command") {
		t.Errorf("exit=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stdout, "VERDICT") {
		t.Error("unknown command must not print a verdict")
	}
}

// logs reading stdin is the analyst path (`zcat fw.gz | leakpatrol logs -`);
// it must work through the injected reader and reach COMPROMISED on a real hit.
func TestLogsFromStdinReachesCompromised(t *testing.T) {
	in := strings.NewReader("2026-08-31T09:12:44Z ALLOW 10.0.3.17 -> 199.91.220.205:80\n")
	stdout, _, code := execCLI(t, in, "logs", "--no-animation", "--color", "never", "-")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.HasPrefix(stdout, "VERDICT: COMPROMISED") {
		t.Errorf("an egress hit from stdin is COMPROMISED:\n%s", stdout)
	}
}
