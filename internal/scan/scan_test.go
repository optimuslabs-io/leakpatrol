// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Test files may spell the indicators out: the test binary is never shipped.

func TestMarkersAreAssembledCorrectly(t *testing.T) {
	want := map[string]string{
		MarkerDomain:       "coder-infra.com",
		MarkerIP:           "199.91.220.205",
		MarkerPath:         "/cli/check",
		MarkerHeader:       "x-cli-token",
		MarkerSentinel:     "data.external.telemetry",
		MarkerScriptDocker: "dlp-docker.sh",
		MarkerScript:       "dlp.sh",
	}
	for got, expected := range want {
		if got != expected {
			t.Errorf("marker assembled to %q, want %q", got, expected)
		}
	}
}

// A scanner that stores the indicator it hunts for CONTAINS that indicator, so it
// finds itself. markers.go stores them reversed; this compiles the real binary
// and greps it so nobody undoes that by writing a literal back somewhere -- in
// Go source, in the embedded SQL, or in the logo tagline.
func TestCompiledBinaryDoesNotContainItsOwnMarkers(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	bin := filepath.Join(t.TempDir(), "leakpatrol-selftest")
	build := exec.Command("go", "build", "-o", bin, "../../cmd/leakpatrol")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	blob, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range TextMarkers() {
		if bytes.Contains(bytes.ToLower(blob), []byte(m.Value)) {
			t.Errorf("the compiled binary contains the contiguous marker %q; leakpatrol will flag itself", m.Value)
		}
	}
	for _, s := range ScriptNames() {
		if bytes.Contains(bytes.ToLower(blob), []byte(s)) {
			t.Errorf("the compiled binary contains the payload filename %q", s)
		}
	}
	if !bytes.Contains(blob, []byte(rev(MarkerDomain))) {
		t.Error("the reversed marker is not in the binary either; this test is not testing what it thinks it is")
	}
}

func TestScanLinesFindsMarkersCaseInsensitively(t *testing.T) {
	input := strings.Join([]string{
		"nothing here",
		"curl -H 'X-CLI-Token: abc' http://WWW.CODER-INFRA.COM/cli/check",
		"2026-08-31 dst=199.91.220.205",
		"module.aider.data.external.telemetry: Reading...",
	}, "\n")
	var hits []Hit
	if err := ScanLines(strings.NewReader(input), TextMarkers(), func(h Hit) bool { hits = append(hits, h); return true }); err != nil {
		t.Fatal(err)
	}
	byLine := map[int][]string{}
	for _, h := range hits {
		byLine[h.Line] = append(byLine[h.Line], h.Marker.Label)
	}
	if len(byLine[1]) != 0 {
		t.Errorf("line 1 should not match: %v", byLine[1])
	}
	if len(byLine[2]) != 3 {
		t.Errorf("line 2 should match domain, path and header, got %v", byLine[2])
	}
	if len(byLine[3]) != 1 {
		t.Errorf("line 3 should match the IP, got %v", byLine[3])
	}
	if len(byLine[4]) != 1 || byLine[4][0] != "Terraform sentinel (harvester data source)" {
		t.Errorf("line 4 should match the sentinel, got %v", byLine[4])
	}
	for _, h := range hits {
		if h.Line == 4 && h.Marker.Egress {
			t.Error("the sentinel must not be classified as egress")
		}
	}
}

func TestScanLinesStopsWhenAsked(t *testing.T) {
	input := "199.91.220.205\n199.91.220.205\n199.91.220.205\n"
	n := 0
	_ = ScanLines(strings.NewReader(input), TextMarkers(), func(Hit) bool { n++; return false })
	if n != 1 {
		t.Errorf("expected early stop after 1 hit, got %d", n)
	}
}

func TestScanLinesReportsOverlongLine(t *testing.T) {
	long := strings.Repeat("a", maxLine+10)
	err := ScanLines(strings.NewReader(long), TextMarkers(), func(Hit) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "4 MiB") {
		t.Errorf("expected the over-long line error, got %v", err)
	}
}

func TestFindTelemetryBlock(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    int
	}{
		{"main.tf", "resource \"x\" \"y\" {}\n\ndata \"external\" \"telemetry\" {\n  program = [\"sh\"]\n}\n", 3},
		{"main.tf", "data   \"external\"\t\"telemetry\"{", 1},
		{"main.tf", "data \"external\" \"other\" {}", 0},
		{"main.tf", "# data \"external\" \"telemetry\" mentioned in a comment", 0}, // no block opener: not a declaration
		{"main.tf.json", `{"data": {"external": {"telemetry": {"program": ["sh"]}}}}`, 1},
		{"main.tf.json", `{"data": {"external": {"foo": {}}}}`, 0},
		{"main.tf", "", 0},
	}
	for _, c := range cases {
		if got := FindTelemetryBlock(c.name, []byte(c.content)); got != c.want {
			t.Errorf("%s %q: got line %d, want %d", c.name, c.content, got, c.want)
		}
	}
}

func TestIsScriptName(t *testing.T) {
	for _, n := range []string{"dlp.sh", "DLP.SH", "/x/y/dlp-docker.sh", `C:\work\dlp.sh`} {
		if !IsScriptName(n) {
			t.Errorf("%q should be a script name", n)
		}
	}
	for _, n := range []string{"dvr.sh", "dlp.sh.bak", "help.sh", "dlp"} {
		if IsScriptName(n) {
			t.Errorf("%q should NOT be a script name", n)
		}
	}
}

func TestPayloadHashesLookRight(t *testing.T) {
	if len(Payloads) != 6 {
		t.Fatalf("advisory lists 6 payload hashes, table has %d", len(Payloads))
	}
	for h, p := range Payloads {
		if len(h) != 64 || strings.ToLower(h) != h {
			t.Errorf("hash %q is not lower-case 64-hex", h)
		}
		if p.SHA256 != h || p.Label == "" {
			t.Errorf("payload %q not initialised: %+v", h, p)
		}
	}
	if _, ok := MatchPayload(DigestBytes([]byte("not the payload"))); ok {
		t.Error("random bytes matched a payload hash")
	}
	if _, ok := MatchPayload("7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398"); !ok {
		t.Error("the docker-variant hash from the advisory must match")
	}
}

func TestIsText(t *testing.T) {
	if !IsText([]byte("plain\ntext\n")) {
		t.Error("text misclassified")
	}
	if IsText([]byte("ELF\x00\x01\x02")) {
		t.Error("binary misclassified")
	}
}
