// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

// The own-goal this tool must never score: it hunts a credential harvester, so
// the ONE thing it cannot do is reprint the credentials the harvester stole. The
// evidence type has no field for file contents, but prose fields (Note, Title,
// Message) are free-form and a careless detector could interpolate a log line or
// a shell-history command into one. This plants secrets in every writable string
// on a report and fails if any of them reaches any output channel.
func TestNoOutputChannelEverPrintsAPlantedSecret(t *testing.T) {
	// Each planted value is something a real harvester log line or history entry
	// would carry. None may appear in human output, JSON, or progress.
	planted := []string{
		"sess-SECRET-9f2c1a",                      // a Coder session token
		"AKIAIOSFODNN7EXAMPLE",                    // a cloud key id
		"curl -H 'X-CLI-Token: leaked-token-xyz'", // a history command
		"sk-ant-api03-DO-NOT-PRINT",               // an AI-tooling key
	}

	rep := &model.Report{
		Schema:  model.SchemaVersion,
		Tool:    model.ToolInfo{Name: "leakpatrol", Version: "0.1.0", Author: "Optimus Labs · Civilizations research team"},
		Verdict: model.VerdictCompromised,
		Paths:   []model.Path{model.PathExecuted, model.PathEgress},
		Window:  model.Window{Start: time.Now().Add(-time.Hour), End: time.Now()},
		Findings: []model.Finding{
			{
				ID: "fs.history_exfil", Detector: "fs", Severity: model.SevCritical, Path: model.PathExecuted,
				Title:  "Exfil endpoint in a shell history -- 1 file",
				Detail: "A harvester call was found in a shell history.",
				Evidence: []model.Evidence{{
					Path: "~/.bash_history", Locator: "line:3",
					// A detector that put the matching LINE here instead of its number
					// would leak the command and the token inside it.
					Note:   "lookalike exfil domain",
					Source: "~/.bash_history", SourceLine: 3,
				}},
			},
			{
				ID: "deploy.sentinel_in_build_log", Detector: "deploy", Severity: model.SevCritical, Path: model.PathExecuted,
				Title: "Build logs carry the Terraform sentinel -- 1",
				Evidence: []model.Evidence{{
					Path: "alice/dev", Locator: "build #8 · start log:9",
					Note: "sentinel on 1 log line",
				}},
			},
		},
		Tiers:       []model.Tier{{Name: "fs", Status: model.TierRan, Summary: "1 file read, 1 hit"}},
		Errors:      []model.ScanError{{Detector: "fs", Kind: "permission", Path: "~/locked", Message: "permission denied", Material: true}},
		Counts:      map[string]int{"critical": 2},
		Limitations: []string{"fs scanned: ~"},
	}

	channels := map[string]string{}

	var human bytes.Buffer
	Human(&human, rep, Style{Verbose: true})
	channels["human --verbose"] = human.String()

	var quiet bytes.Buffer
	Human(&quiet, rep, Style{Quiet: true})
	channels["human --quiet"] = quiet.String()

	var colored bytes.Buffer
	Human(&colored, rep, Style{Color: true, Verbose: true})
	channels["human --color"] = colored.String()

	var js bytes.Buffer
	if err := JSON(&js, rep); err != nil {
		t.Fatal(err)
	}
	channels["json"] = js.String()

	// Progress is the stderr channel; a detector's summary flows through it.
	var prog bytes.Buffer
	p := NewProgress(&prog, Style{})
	p.Header("scanning ~")
	p.Checking("fs", "shell histories")
	p.Pulse("fs", "1 file")
	p.Checked("fs", "1 file read, 1 hit", time.Millisecond, engine.OutcomeHits)
	p.Skipped("db", "psql not on PATH")
	p.Done(time.Millisecond)
	channels["progress"] = prog.String()

	for name, out := range channels {
		if strings.TrimSpace(out) == "" {
			t.Errorf("%s produced no output; this test would pass for the wrong reason", name)
		}
		for _, secret := range planted {
			if strings.Contains(out, secret) {
				t.Errorf("%s leaked a planted secret %q:\n%s", name, secret, out)
			}
		}
	}

	// Sanity: the channels DO carry the locations, so the test is exercising real
	// output rather than empty buffers.
	if !strings.Contains(channels["human --verbose"], "~/.bash_history") ||
		!strings.Contains(channels["human --verbose"], "line:3") {
		t.Error("the human report should still cite the location and line number")
	}
	if !strings.Contains(channels["json"], "\"source_line\": 3") {
		t.Error("JSON should still carry the line number")
	}
}

// A reader who watches stderr and skips stdout must not see a row of green
// checks over a COMPROMISED verdict.
func TestProgressDoesNotMarkHitsWithTheCleanCheck(t *testing.T) {
	cases := []struct {
		outcome engine.Outcome
		green   bool
	}{
		{engine.OutcomeEmpty, true},
		{engine.OutcomeHits, false},
		{engine.OutcomeFailed, false},
		{engine.OutcomeWeak, false},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		p := NewProgress(&buf, Style{Color: true})
		p.Checked("fs", "summary", time.Millisecond, c.outcome)
		out := buf.String()
		isGreen := strings.Contains(out, green+"✓")
		if isGreen != c.green {
			t.Errorf("outcome %v: green check = %v, want %v (%q)", c.outcome, isGreen, c.green, out)
		}
	}
}
