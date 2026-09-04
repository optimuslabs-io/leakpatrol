// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"testing"

	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

func kinds(ms []Match) map[Kind]Match {
	out := map[Kind]Match{}
	for _, m := range ms {
		out[m.Kind] = m
	}
	return out
}

func TestTelemetryBlockInTerraform(t *testing.T) {
	ms := kinds(File("/work/.terraform/modules/aider/main.tf", []byte("data \"external\" \"telemetry\" {\n program = [\"sh\", \"dlp.sh\"]\n}\n"), false, true))
	m, ok := ms[KindTelemetry]
	if !ok || m.Line != 1 {
		t.Fatalf("expected a telemetry match on line 1, got %+v", ms)
	}
	if m.Kind.Severity() != model.SevHigh || m.Kind.Path() != model.PathPresent {
		t.Errorf("telemetry block must be HIGH / present, got %v %v", m.Kind.Severity(), m.Kind.Path())
	}
}

func TestHistoryHitIsCriticalAndExecuted(t *testing.T) {
	ms := kinds(File("/home/coder/.bash_history", []byte("ls\ncurl http://www.coder-infra.com/cli/check\n"), false, true))
	m, ok := ms[KindHistory]
	if !ok || m.Line != 2 {
		t.Fatalf("expected a history match on line 2, got %+v", ms)
	}
	if m.Kind.Severity() != model.SevCritical || m.Kind.Path() != model.PathExecuted {
		t.Errorf("history hit must be CRITICAL / executed")
	}
}

func TestIndicatorInModuleTreeVsElsewhere(t *testing.T) {
	body := []byte("endpoint = \"199.91.220.205\"\n")
	if _, ok := kinds(File("/tmp/x/.terraform/modules/zed/vars.txt", body, false, true))[KindModule]; !ok {
		t.Error("an indicator under .terraform/ must be a module hit")
	}
	if _, ok := kinds(File("/home/me/notes.txt", body, false, true))[KindReference]; !ok {
		t.Error("an indicator in a random text file must be a reference hit")
	}
	if KindReference.Severity() != model.SevMedium {
		t.Error("reference hits are MEDIUM: real, but a human decides")
	}
}

func TestScriptNameWithoutMatchingHashIsWeak(t *testing.T) {
	ms := kinds(File("/opt/dlp.sh", []byte("#!/bin/sh\necho benign\n"), false, true))
	m, ok := ms[KindName]
	if !ok {
		t.Fatalf("expected a weak name match, got %+v", ms)
	}
	if m.Kind.Severity() != model.SevLow {
		t.Error("a filename alone is LOW")
	}
	if _, ok := ms[KindPayload]; ok {
		t.Error("benign bytes must never be a payload match")
	}
}

func TestBinaryContentIsNotTextScanned(t *testing.T) {
	ms := File("/usr/bin/thing", []byte("\x7fELF\x00\x00 199.91.220.205"), false, false)
	if len(ms) != 0 {
		t.Errorf("binary files must not be text-scanned, got %+v", ms)
	}
}

func TestTruncatedFileIsNotHashed(t *testing.T) {
	// A truncated buffer cannot be hashed meaningfully; it must still be text-scanned.
	ms := kinds(File("/var/log/x.log", []byte("x-cli-token: y\n"), true, true))
	if _, ok := ms[KindReference]; !ok {
		t.Errorf("truncated text must still be scanned, got %+v", ms)
	}
}

func TestCollectorGroupsByKindAndCounts(t *testing.T) {
	c := &Collector{Tier: "fs"}
	c.Add("~/a/main.tf", []Match{{Kind: KindTelemetry, Line: 3, Label: "t"}}, 10)
	c.Add("~/b/main.tf", []Match{{Kind: KindTelemetry, Line: 9, Label: "t"}}, 10)
	c.Add("~/.bash_history", []Match{{Kind: KindHistory, Line: 2, Label: "h", Hits: 4}}, 10)
	fs := c.Findings()
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fs))
	}
	if fs[0].ID != "fs.telemetry_block" || len(fs[0].Evidence) != 2 {
		t.Errorf("unexpected first finding %+v", fs[0])
	}
	if fs[1].Evidence[0].Note != "h (+3 more indicator matches)" || fs[1].Evidence[0].Locator != "line:2" {
		t.Errorf("unexpected evidence %+v", fs[1].Evidence[0])
	}
	if c.Hits != 3 {
		t.Errorf("hits = %d", c.Hits)
	}
}
