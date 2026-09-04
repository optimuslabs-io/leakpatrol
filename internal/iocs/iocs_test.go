// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package iocs

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The IoC export is what other tooling imports, so its shape is a contract: six
// hashes, the advisory id, and the exact window every in-window judgement is made
// against. A typo here silently mis-scopes someone else's hunt.
func TestBuildMatchesTheAdvisory(t *testing.T) {
	s := Build()

	if s.Advisory != "GHSA-vx42-ghc9-gw65" {
		t.Errorf("advisory = %q", s.Advisory)
	}
	if !strings.Contains(s.AdvisoryURL, s.Advisory) {
		t.Errorf("advisory_url should reference the advisory: %q", s.AdvisoryURL)
	}
	if !strings.Contains(s.CuratedBy, "Civilizations") || !strings.Contains(s.CuratedBy, "Optimus Labs") {
		t.Errorf("curated_by = %q", s.CuratedBy)
	}

	wantStart := time.Date(2026, 8, 31, 7, 35, 0, 0, time.UTC)
	wantEnd := time.Date(2026, 8, 31, 21, 45, 0, 0, time.UTC)
	if !s.Window.Start.Equal(wantStart) || !s.Window.End.Equal(wantEnd) {
		t.Errorf("window = %s..%s, want %s..%s", s.Window.Start, s.Window.End, wantStart, wantEnd)
	}
	if !Window.Start.Equal(wantStart) || !Window.End.Equal(wantEnd) {
		t.Error("the exported Window must match the advisory: every in-window judgement uses it")
	}

	if len(s.Payloads) != 6 {
		t.Fatalf("the advisory publishes 6 payload hashes, got %d", len(s.Payloads))
	}
	seen := map[string]bool{}
	for _, p := range s.Payloads {
		if !hex64.MatchString(p.SHA256) {
			t.Errorf("payload hash is not lower-case 64-hex: %q", p.SHA256)
		}
		if seen[p.SHA256] {
			t.Errorf("duplicate payload hash %q", p.SHA256)
		}
		seen[p.SHA256] = true
		if p.Variant == "" || p.Filename == "" {
			t.Errorf("payload missing labels: %+v", p)
		}
	}
	// The one hash quoted (truncated) in the public briefing, in full.
	if !seen["7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398"] {
		t.Error("the dlp-docker.sh hash from the advisory is missing")
	}

	if s.Domain != "www.coder-infra.com" || s.IP != "199.91.220.205" {
		t.Errorf("network indicators wrong: %q %q", s.Domain, s.IP)
	}
	if s.Header != "X-CLI-Token" {
		t.Errorf("header = %q (canonical spelling matters for Sigma/SIEM import)", s.Header)
	}
	if s.Sentinel != "data.external.telemetry" {
		t.Errorf("sentinel = %q", s.Sentinel)
	}
	if !strings.Contains(s.URL, s.Domain) || !strings.Contains(s.URL, "/cli/check") {
		t.Errorf("url = %q", s.URL)
	}

	// These are the module names the advisory labels individual harvester builds
	// with. They are exported to help an operator prioritise, never to bound a
	// scan: no detector consults them (see VariantModules).
	for _, want := range []string{"aider", "rstudio-server", "windows-rdp", "zed"} {
		found := false
		for _, p := range s.VariantModules {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("harvester variant module %q missing", want)
		}
	}
	for _, want := range []string{"2.37.0", "2.36.4", "2.35.7", "2.34.9"} {
		found := false
		for _, b := range s.PatchedBuilds {
			if b == want {
				found = true
			}
		}
		if !found {
			t.Errorf("patched build %q missing", want)
		}
	}
	for _, want := range []string{"T1195.002", "T1552", "T1567.002"} {
		found := false
		for _, tech := range s.Techniques {
			if tech == want {
				found = true
			}
		}
		if !found {
			t.Errorf("ATT&CK technique %q missing", want)
		}
	}
}

func TestWriteEmitsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("iocs output must be valid JSON: %v\n%s", err, buf.String())
	}
	for _, k := range []string{"advisory", "window", "domain", "ip", "payloads", "curated_by", "attack_techniques"} {
		if _, ok := back[k]; !ok {
			t.Errorf("key %q missing from the JSON export", k)
		}
	}
}
