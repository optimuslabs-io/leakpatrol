// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package engine runs the detection tiers and turns their findings into a verdict.
package engine

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/optimuslabs-io/leakpatrol/internal/buildinfo"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

// Env is everything a detector may need. Detectors read it; only main writes it.
type Env struct {
	Home string

	// Roots for the fs tier. Empty means the per-OS defaults.
	Roots []string
	// Logs for the logs tier; "-" is stdin.
	Logs []string
	// Images for the image tier: a tar path, "-" for stdin, or an image reference
	// to hand to a detected container CLI.
	Images []string

	// Server and Token drive the deploy tier. Offline disables it outright.
	Server  string
	Token   string
	Offline bool

	// DSN drives the db tier.
	DSN string

	// MaxFileSize caps how much of any single file is read and hashed.
	MaxFileSize int64

	Window model.Window

	// Stdin is what "-" reads. Injected so tests can drive it.
	Stdin io.Reader

	// Progress lets a long-running detector narrate. Nil when nothing is watching.
	Progress Progress
}

// Result is what one tier returns.
type Result struct {
	Findings    []model.Finding
	Errors      []model.ScanError
	Limitations []string
	// Summary is the detector's own one-line account of what it found (or did not),
	// printed on the progress line. An empty summary is rendered as "nothing found".
	Summary string
}

// Detector is one tier. Ready reports why the tier cannot run in this Env (empty
// means it can); the engine records that reason in the report so a skipped tier
// is visible, not silent.
//
// Material says whether SKIPPING this tier is a hole in the verdict. Only the
// deploy tier is: without the deployment's own view there is no answer to "did
// this Coder pull the module". An absent image tar, an absent flow-log export, no
// psql, no coder CLI -- those are coverage lines in the report, not a reason to
// downgrade a CLEAN to INDETERMINATE. A verdict that is INDETERMINATE on every
// laptop is a verdict operators learn to ignore, which is worse than a slightly
// looser CLEAN with an honest COVERAGE table under it.
type Detector interface {
	Name() string
	Describe() string
	Ready(env *Env) (skipReason string)
	Material() bool
	Run(ctx context.Context, env *Env) Result
}

type Engine struct {
	Detectors       []Detector
	DetectorTimeout time.Duration
	Progress        Progress
	// All marks a run that asked for every tier: a skipped tier then degrades the
	// verdict. A single-tier run (`leakpatrol fs /`) is judged on that tier alone.
	All bool
}

func (e *Engine) Run(ctx context.Context, env *Env) *model.Report {
	if e.Progress == nil {
		e.Progress = nopProgress{}
	}
	if _, ok := e.Progress.(nopProgress); ok {
		env.Progress = nil
	} else {
		env.Progress = e.Progress
	}
	started := time.Now()
	rep := &model.Report{
		Schema:    model.SchemaVersion,
		StartedAt: started.UTC(),
		Tool: model.ToolInfo{
			Name: "leakpatrol", Version: buildinfo.Version, Commit: buildinfo.Commit,
			BuiltAt: buildinfo.Date, GoVersion: buildinfo.GoVersion(),
			Author: buildinfo.Attribution, Advisory: buildinfo.Advisory, Source: buildinfo.Repo,
		},
		Host:   model.HostInfo{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Home: env.Home},
		Window: env.Window,
		Counts: map[string]int{},
	}

	for _, d := range e.Detectors {
		if ctx.Err() != nil {
			rep.Tiers = append(rep.Tiers, model.Tier{Name: d.Name(), Status: model.TierSkipped, Reason: "interrupted"})
			continue
		}
		if reason := d.Ready(env); reason != "" {
			e.Progress.Skipped(d.Name(), reason)
			rep.Tiers = append(rep.Tiers, model.Tier{Name: d.Name(), Status: model.TierSkipped, Reason: reason, MaterialGap: e.All && d.Material()})
			continue
		}
		e.Progress.Checking(d.Name(), d.Describe())
		start := time.Now()
		r := e.runOne(ctx, d, env)
		took := time.Since(start)
		e.Progress.Checked(d.Name(), r.Summary, took, outcome(r))
		rep.Findings = append(rep.Findings, r.Findings...)
		rep.Errors = append(rep.Errors, r.Errors...)
		rep.Limitations = append(rep.Limitations, r.Limitations...)
		rep.Tiers = append(rep.Tiers, model.Tier{
			Name: d.Name(), Status: model.TierRan, Summary: r.Summary, Duration: took.Round(time.Millisecond).String(),
		})
	}

	finalize(rep, e.All, time.Since(started))
	e.Progress.Done(time.Since(started))
	return rep
}

// outcome grades a tier's result for the progress line: hits beat failure beats
// weak beats empty, so a tier that both found something and hit an error reads as
// a find (the error still lands in BLIND SPOTS).
func outcome(r Result) Outcome {
	weak := false
	for _, f := range r.Findings {
		if f.Severity >= model.SevMedium {
			return OutcomeHits
		}
		if f.Severity == model.SevLow {
			weak = true
		}
	}
	for _, e := range r.Errors {
		if e.Material {
			return OutcomeFailed
		}
	}
	if weak {
		return OutcomeWeak
	}
	return OutcomeEmpty
}

// runOne isolates a detector. A panic in the image reader must still let the
// egress-log findings reach the report: a crash that produces no findings reads
// exactly like a clean host, which is the worst failure this tool could have.
func (e *Engine) runOne(ctx context.Context, d Detector, env *Env) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res.Errors = append(res.Errors, model.ScanError{
				Detector: d.Name(), Kind: "panic", Material: true,
				// The stack is deliberately not included: a panic on a bad slice could
				// carry file bytes into it, and this string ends up in the JSON report.
				Message: fmt.Sprint(r),
			})
		}
	}()
	dctx := ctx
	if e.DetectorTimeout > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, e.DetectorTimeout)
		defer cancel()
	}
	res = d.Run(dctx, env)
	if dctx.Err() != nil {
		res.Errors = append(res.Errors, model.ScanError{
			Detector: d.Name(), Kind: "timeout", Material: true,
			Message: "the tier did not finish before its deadline; findings above this point are partial",
		})
	}
	return res
}

func finalize(rep *model.Report, all bool, elapsed time.Duration) {
	rep.Duration = elapsed.Round(time.Millisecond).String()
	for _, e := range rep.Errors {
		if e.Material {
			rep.Degraded = true
			break
		}
	}
	ran := map[string]bool{}
	anyRan := false
	for _, t := range rep.Tiers {
		if t.Status == model.TierSkipped && t.MaterialGap {
			rep.Degraded = true
		}
		ran[t.Name] = t.Status == model.TierRan
		anyRan = anyRan || ran[t.Name]
	}
	// Belt and braces under main's "an explicit tier that cannot run is a tool
	// error": a report in which NOTHING ran can never say CLEAN.
	if !anyRan {
		rep.Degraded = true
	}
	// The one optional skip that changes what the verdict can see. The API judges
	// a template version by its JOB timestamps; Coder's query 1 judges the module
	// CACHE entry (files.created_at). A version whose cache was populated inside
	// the window but whose job is stamped outside it -- and every workspace built
	// from it afterwards -- is visible only to the db tier.
	if all && ran["deploy"] && !ran["db"] {
		rep.Limitations = append(rep.Limitations,
			"db tier did not run, so two things the deploy tier structurally cannot see went unchecked: (1) a module cached "+
				"DURING the window on a version built AFTER it (only template_version_terraform_values.cached_module_files / "+
				"files.created_at shows this); and (2) a template DRY-RUN in the window -- dry-run jobs are not enumerable over "+
				"the API, so only query 3's scan of provisioner_job_logs catches them. Run `leakpatrol db`, or paste "+
				"`leakpatrol db --print-only` into any Postgres client.")
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		if rep.Findings[i].Severity != rep.Findings[j].Severity {
			return rep.Findings[i].Severity > rep.Findings[j].Severity
		}
		return rep.Findings[i].ID < rep.Findings[j].ID
	})
	for _, f := range rep.Findings {
		rep.Counts[f.Severity.String()]++
	}
	rep.Paths = paths(rep.Findings)
	rep.Verdict = verdict(rep)
	rep.Limitations = dedupe(append(rep.Limitations, standingLimitations()...))
}

// verdict is deliberately conservative. The rule that matters is the last one: a
// degraded or partial scan can never come back CLEAN, because "I could not check
// the database and found nothing on disk" is not "there is nothing here".
func verdict(rep *model.Report) model.Verdict {
	executed, exposure, weak := false, false, false
	for _, f := range rep.Findings {
		switch {
		case f.Severity >= model.SevHigh && f.Executed():
			executed = true
		case f.Severity >= model.SevMedium:
			exposure = true
		case f.Severity == model.SevLow:
			weak = true
		}
	}
	switch {
	case executed:
		return model.VerdictCompromised
	case exposure:
		return model.VerdictExposed
	case weak, rep.Degraded:
		return model.VerdictIndeterminate
	default:
		return model.VerdictClean
	}
}

// paths collects the exposure paths implicated by findings at MEDIUM or above,
// worst first. LOW findings are weak signals and do not implicate a path.
func paths(findings []model.Finding) []model.Path {
	rank := map[model.Path]int{
		model.PathEgress: 5, model.PathExecuted: 4, model.PathWorkspaceBuild: 3,
		model.PathTemplateImport: 2, model.PathPresent: 1,
	}
	seen := map[model.Path]bool{}
	var out []model.Path
	for _, f := range findings {
		if f.Severity < model.SevMedium || f.Path == "" || seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		out = append(out, f.Path)
	}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i]] > rank[out[j]] })
	return out
}

func standingLimitations() []string {
	out := []string{
		"leakpatrol only sees what is still there. A module cache already purged, an egress log that rotated, " +
			"or a provisioner pod that was recycled leaves no trace -- and none of that undoes a credential that already left.",
		"Indicators are vendor-attested (GHSA-vx42-ghc9-gw65). No third party has independently reproduced them; " +
			"absence from reputation feeds is expected for a 14-hour, pull-based, vendor-infrastructure attack and is not an all-clear.",
	}
	if runtime.GOOS == "darwin" {
		out = append(out, "On macOS, ~/Documents, ~/Desktop, ~/Downloads and ~/Library/Containers are protected by TCC. "+
			"If your terminal lacks Full Disk Access those directories were skipped.")
	}
	if runtime.GOOS == "windows" {
		out = append(out, "On Windows there is no filesystem-device check, so the walker uses reparse points to avoid "+
			"crossing mounts. A volume mounted under a junction may have been skipped.")
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// Plural renders a count with its noun: "1 build", "2 builds".
func Plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	if strings.HasSuffix(noun, "y") {
		return strconv.Itoa(n) + " " + strings.TrimSuffix(noun, "y") + "ies"
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
