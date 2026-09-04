// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

type fake struct {
	name     string
	skip     string
	res      Result
	panic    bool
	material bool
}

func (f fake) Name() string     { return f.name }
func (f fake) Describe() string { return "fake" }
func (f fake) Material() bool   { return f.material }
func (f fake) Ready(*Env) string {
	return f.skip
}
func (f fake) Run(context.Context, *Env) Result {
	if f.panic {
		panic("boom")
	}
	return f.res
}

func finding(sev model.Severity, p model.Path) model.Finding {
	return model.Finding{ID: "x", Detector: "fake", Severity: sev, Path: p, Evidence: []model.Evidence{{Path: "p"}}}
}

func TestVerdictMatrix(t *testing.T) {
	cases := []struct {
		name string
		dets []Detector
		all  bool
		want model.Verdict
	}{
		{"nothing, all ran", []Detector{fake{name: "a"}}, false, model.VerdictClean},
		{"nothing, material tier skipped in all-mode", []Detector{fake{name: "a"}, fake{name: "deploy", skip: "no token", material: true}}, true, model.VerdictIndeterminate},
		{"nothing, optional tier skipped in all-mode", []Detector{fake{name: "a"}, fake{name: "image", skip: "no tar"}}, true, model.VerdictClean},
		{"nothing, material tier skipped in single-mode", []Detector{fake{name: "a"}, fake{name: "deploy", skip: "no token", material: true}}, false, model.VerdictClean},
		{"nothing ran at all is never clean", []Detector{fake{name: "deploy", skip: "no token"}}, false, model.VerdictIndeterminate},
		{"weak only", []Detector{fake{name: "a", res: Result{Findings: []model.Finding{finding(model.SevLow, model.PathPresent)}}}}, false, model.VerdictIndeterminate},
		{"medium pulled", []Detector{fake{name: "a", res: Result{Findings: []model.Finding{finding(model.SevMedium, model.PathTemplateImport)}}}}, false, model.VerdictExposed},
		{"high present", []Detector{fake{name: "a", res: Result{Findings: []model.Finding{finding(model.SevHigh, model.PathPresent)}}}}, false, model.VerdictExposed},
		{"critical executed", []Detector{fake{name: "a", res: Result{Findings: []model.Finding{finding(model.SevCritical, model.PathExecuted)}}}}, false, model.VerdictCompromised},
		{"critical egress", []Detector{fake{name: "a", res: Result{Findings: []model.Finding{finding(model.SevCritical, model.PathEgress)}}}}, false, model.VerdictCompromised},
		{"material error, nothing found", []Detector{fake{name: "a", res: Result{Errors: []model.ScanError{{Material: true}}}}}, false, model.VerdictIndeterminate},
		{"panic never reads as clean", []Detector{fake{name: "a", panic: true}}, false, model.VerdictIndeterminate},
		{"info only is clean", []Detector{fake{name: "a", res: Result{Findings: []model.Finding{finding(model.SevInfo, "")}}}}, false, model.VerdictClean},
	}
	for _, c := range cases {
		e := &Engine{Detectors: c.dets, All: c.all}
		rep := e.Run(context.Background(), &Env{})
		if rep.Verdict != c.want {
			t.Errorf("%s: got %s want %s (degraded=%v tiers=%+v)", c.name, rep.Verdict, c.want, rep.Degraded, rep.Tiers)
		}
	}
}

func TestPathsAreOrderedWorstFirstAndSkipWeak(t *testing.T) {
	e := &Engine{Detectors: []Detector{fake{name: "a", res: Result{Findings: []model.Finding{
		finding(model.SevMedium, model.PathTemplateImport),
		finding(model.SevLow, model.PathPresent),
		finding(model.SevCritical, model.PathExecuted),
	}}}}}
	rep := e.Run(context.Background(), &Env{})
	if len(rep.Paths) != 2 || rep.Paths[0] != model.PathExecuted || rep.Paths[1] != model.PathTemplateImport {
		t.Errorf("paths = %v", rep.Paths)
	}
}

func TestSkippedTierIsRecordedWithReason(t *testing.T) {
	e := &Engine{Detectors: []Detector{fake{name: "db", skip: "psql not on PATH"}}, All: true}
	rep := e.Run(context.Background(), &Env{})
	if len(rep.Tiers) != 1 || rep.Tiers[0].Status != model.TierSkipped || rep.Tiers[0].Reason != "psql not on PATH" || rep.Tiers[0].MaterialGap {
		t.Errorf("tiers = %+v", rep.Tiers)
	}
}

func TestDeployWithoutDbNamesTheCacheGap(t *testing.T) {
	e := &Engine{Detectors: []Detector{fake{name: "deploy", material: true}, fake{name: "db", skip: "no psql"}}, All: true}
	rep := e.Run(context.Background(), &Env{})
	found := false
	for _, l := range rep.Limitations {
		if strings.Contains(l, "cached_module_files") {
			found = true
		}
	}
	if !found || rep.Verdict != model.VerdictClean {
		t.Errorf("expected CLEAN with the cached_module_files limitation, got %s %v", rep.Verdict, rep.Limitations)
	}
}
