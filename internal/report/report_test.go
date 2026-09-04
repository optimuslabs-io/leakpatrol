// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

func sample() *model.Report {
	return &model.Report{
		Schema:  model.SchemaVersion,
		Tool:    model.ToolInfo{Name: "leakpatrol", Version: "0.1.0", Author: "Optimus Labs · Civilizations research team"},
		Verdict: model.VerdictCompromised,
		Paths:   []model.Path{model.PathExecuted, model.PathTemplateImport},
		Findings: []model.Finding{
			{ID: "deploy.sentinel_in_template_job", Detector: "deploy", Severity: model.SevCritical, Path: model.PathExecuted,
				Title:    "Template import logs carry the Terraform sentinel -- the harvester ran -- 1",
				Evidence: []model.Evidence{{Path: "aider/bad", Locator: "job:j-bad log:2", Note: "sentinel on 1 log line"}}},
			{ID: "fs.script_name", Detector: "fs", Severity: model.SevLow, Path: model.PathPresent, Title: "weak -- 1 file",
				Evidence: []model.Evidence{{Path: "~/x/dlp.sh", Note: "harvester filename"}}},
		},
		Tiers:  []model.Tier{{Name: "deploy", Status: model.TierRan, Summary: "1 template"}, {Name: "db", Status: model.TierSkipped, Reason: "psql not on PATH"}},
		Counts: map[string]int{"critical": 1, "low": 1},
	}
}

func render(rep *model.Report, s Style) string {
	var out bytes.Buffer
	Human(&out, rep, s)
	return out.String()
}

func TestHumanReportLeadsWithVerdictAndRotate(t *testing.T) {
	s := render(sample(), Style{})
	if !strings.HasPrefix(s, "VERDICT: COMPROMISED") {
		t.Errorf("report must lead with the verdict:\n%s", s)
	}
	for _, want := range []string{"ROTATE", "Provisioner environment", "ANTHROPIC_API_KEY", "REMEDIATE", "--purge", "COVERAGE", "skipped", "psql not on PATH", "Civilizations"} {
		if !strings.Contains(s, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// A template-import sentinel implicates the provisioner, not workspace owners
	// and not "the host where it was found".
	if strings.Contains(s, "Per affected workspace owner") || strings.Contains(s, "On the host / image") {
		t.Errorf("ROTATE over-scoped for a template-import finding:\n%s", s)
	}
	if strings.Contains(s, "\x1b[") {
		t.Error("colour off must emit no escape codes")
	}
}

func TestRotateIsScopedToWhereTheFindingCameFrom(t *testing.T) {
	// A hash match on a laptop: host block only, no coderd database line.
	rep := sample()
	rep.Findings = []model.Finding{{ID: "fs.payload_hash", Detector: "fs", Severity: model.SevHigh, Path: model.PathPresent,
		Title: "harvester -- 1 file", Evidence: []model.Evidence{{Path: "~/Downloads/dlp.sh", SHA256: "abc"}}}}
	rep.Verdict, rep.Paths = model.VerdictExposed, []model.Path{model.PathPresent}
	s := render(rep, Style{})
	if !strings.Contains(s, "On the host / image where it was found") {
		t.Errorf("host block missing:\n%s", s)
	}
	if strings.Contains(s, "Coder database password") || strings.Contains(s, "Per affected workspace owner") {
		t.Errorf("a laptop hash match must not read like a coderd compromise:\n%s", s)
	}

	// A workspace build on a tainted version: provisioner AND owners.
	rep.Findings = []model.Finding{{ID: "deploy.workspace_build_on_tainted_version", Detector: "deploy", Severity: model.SevMedium, Path: model.PathWorkspaceBuild,
		Title: "builds -- 1", Evidence: []model.Evidence{{Path: "alice/dev", Locator: "build #8 · start"}}}}
	s = render(rep, Style{})
	if !strings.Contains(s, "Provisioner environment") || !strings.Contains(s, "Per affected workspace owner") {
		t.Errorf("workspace build must implicate provisioner and owners:\n%s", s)
	}

	// db query 3 with a workspace_build job type in the rows: owners too.
	rep.Findings = []model.Finding{{ID: "db.sentinel_in_job_log", Detector: "db", Severity: model.SevCritical, Path: model.PathExecuted,
		Title: "jobs -- 1", Evidence: []model.Evidence{{Path: "alice/dev (aider/v3)", Locator: "workspace_build job:j9"}}}}
	rep.Verdict = model.VerdictCompromised
	if s = render(rep, Style{}); !strings.Contains(s, "Per affected workspace owner") {
		t.Errorf("db sentinel on a workspace_build job must implicate owners:\n%s", s)
	}
}

func TestQuietPrintsOnlyVerdictBlock(t *testing.T) {
	s := render(sample(), Style{Quiet: true})
	// The facts line may POINT at ROTATE; the section itself must not print.
	if strings.Contains(s, "\nROTATE") || strings.Contains(s, "FINDINGS") || strings.Contains(s, "COVERAGE") || !strings.HasPrefix(s, "VERDICT") {
		t.Errorf("quiet output wrong:\n%s", s)
	}
}

func TestCleanReportHasNoRotateOrRemediate(t *testing.T) {
	rep := sample()
	rep.Verdict, rep.Findings, rep.Paths = model.VerdictClean, nil, nil
	rep.Tiers = []model.Tier{{Name: "fs", Status: model.TierRan, Summary: "nothing"}, {Name: "logs", Status: model.TierSkipped, Reason: "no --logs"}}
	s := render(rep, Style{})
	for _, bad := range []string{"ROTATE", "REMEDIATE", "NEXT"} {
		if strings.Contains(s, bad) {
			t.Errorf("a clean report must not contain %s:\n%s", bad, s)
		}
	}
	if !strings.Contains(s, "No indicator found by: fs.") || !strings.Contains(s, "Not run (optional inputs absent; see COVERAGE): logs.") {
		t.Errorf("clean report should name what ran and what did not:\n%s", s)
	}
}

func TestIndeterminateGetsNextNotRemediate(t *testing.T) {
	rep := sample()
	rep.Verdict, rep.Findings, rep.Paths, rep.Degraded = model.VerdictIndeterminate, nil, nil, true
	rep.Tiers = []model.Tier{
		{Name: "deploy", Status: model.TierSkipped, Reason: "--offline", MaterialGap: true},
		{Name: "fs", Status: model.TierRan, Summary: "nothing"},
	}
	s := render(rep, Style{})
	if strings.Contains(s, "REMEDIATE") || strings.Contains(s, "purge") {
		t.Errorf("INDETERMINATE must not tell the operator to purge anything:\n%s", s)
	}
	if !strings.Contains(s, "NEXT") || !strings.Contains(s, "coder login") || !strings.Contains(s, "deployment itself was not asked") {
		t.Errorf("INDETERMINATE must say what to do next:\n%s", s)
	}

	// Nothing ran at all: the sentence must not be "No indicator found by: ."
	rep.Tiers = []model.Tier{{Name: "deploy", Status: model.TierSkipped, Reason: "no token"}}
	s = render(rep, Style{})
	if strings.Contains(s, "found by: .") || !strings.Contains(s, "No tier ran") {
		t.Errorf("zero-tier report wording wrong:\n%s", s)
	}
}

func TestFactsSumTheSameKindAcrossTiers(t *testing.T) {
	rep := sample()
	rep.Verdict, rep.Paths = model.VerdictExposed, []model.Path{model.PathPresent}
	rep.Findings = []model.Finding{
		{ID: "fs.telemetry_block", Detector: "fs", Severity: model.SevHigh, Path: model.PathPresent, Evidence: []model.Evidence{{Path: "a"}}},
		{ID: "image.telemetry_block", Detector: "image", Severity: model.SevHigh, Path: model.PathPresent, Evidence: []model.Evidence{{Path: "b"}}},
	}
	s := render(rep, Style{})
	if !strings.Contains(s, "telemetry block in 2 files") || strings.Count(s, "telemetry block in") > 1 {
		t.Errorf("facts should sum, not repeat:\n%s", s)
	}
}

func TestJSONIsValidAndNullFree(t *testing.T) {
	rep := &model.Report{Schema: model.SchemaVersion, Verdict: model.VerdictClean}
	var out bytes.Buffer
	if err := JSON(&out, rep); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(out.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"findings", "errors", "tiers", "paths", "limitations"} {
		if back[k] == nil {
			t.Errorf("%s must be an empty array, not null", k)
		}
	}
}

func TestLogoHasNoMarkersAndFitsATerminal(t *testing.T) {
	var out bytes.Buffer
	plainLogo(&out, Style{})
	for _, line := range strings.Split(out.String(), "\n") {
		if n := len([]rune(line)); n > 90 {
			t.Errorf("logo line is %d columns: %q", n, line)
		}
	}
	low := strings.ToLower(out.String())
	for _, bad := range []string{"infra", "199.91", "cli/check", "telemetry", "dlp"} {
		if strings.Contains(low, bad) {
			t.Errorf("logo/subtitle contains an indicator fragment %q", bad)
		}
	}
}

func TestWrapAndVisibleWidth(t *testing.T) {
	if visibleWidth("\x1b[31mred\x1b[0m") != 3 {
		t.Error("visibleWidth must ignore SGR")
	}
	w := wrap("one two three four", 9, "  ")
	if w != "one two\n  three\n  four" {
		t.Errorf("wrap = %q", w)
	}
}
