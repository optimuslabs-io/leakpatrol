// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package report renders the scan for a person (human.go), for a machine
// (json.go), and narrates it while it runs (progress.go).
package report

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

type Style struct {
	Color   bool
	Quiet   bool
	Verbose bool
}

// Colour is semantic, not decorative:
//
//	red    -- act now: COMPROMISED, a CRITICAL finding, a credential class to rotate
//	yellow -- exposure: EXPOSED / INDETERMINATE, a MEDIUM finding, a skipped tier
//	green  -- good: CLEAN, a tier that ran
//	cyan   -- a location the reader will act on
//	dim    -- context and provenance
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	cyan   = "\033[36m"
)

func (s Style) c(code, text string) string {
	if !s.Color {
		return text
	}
	return code + text + reset
}

// Paint applies a semantic role ("act", "warn", "good", "where", "dim") for
// callers outside the package, so main can print a preflight line in the same
// vocabulary without reaching for escape codes of its own.
func (s Style) Paint(role, text string) string {
	switch role {
	case "act":
		return s.c(red, text)
	case "warn":
		return s.c(yellow, text)
	case "good":
		return s.c(green, text)
	case "where":
		return s.c(cyan, text)
	case "dim":
		return s.c(dim, text)
	}
	return text
}

// maxRows bounds what the TERMINAL prints per finding. --json keeps every row;
// the true total is always in the finding's title.
const maxRows = 10

// Human writes the report a person reads: verdict and facts first, then what to
// rotate, then how to remediate, then the evidence, then coverage -- and at the
// very bottom what this tool cannot see.
func Human(w io.Writer, rep *model.Report, s Style) {
	verdictBanner(w, rep, s)
	if s.Quiet {
		footer(w, rep, s)
		return
	}
	rotate(w, rep, s)
	remediate(w, rep, s)
	next(w, rep, s)
	findings(w, rep, s)
	coverage(w, rep, s)
	blindSpots(w, rep, s)
	limitations(w, rep, s)
	footer(w, rep, s)
}

func verdictBanner(w io.Writer, rep *model.Report, s Style) {
	var color string
	switch rep.Verdict {
	case model.VerdictCompromised:
		color = red
	case model.VerdictExposed, model.VerdictIndeterminate:
		color = yellow
	default:
		color = green
	}
	fmt.Fprintln(w, s.c(color+bold, "VERDICT: "+string(rep.Verdict)))
	for _, line := range facts(rep) {
		fmt.Fprintln(w, "  "+line)
	}
	fmt.Fprintln(w)
}

// factKind classifies a finding for the telegraph lines. Kinds are summed across
// tiers, so a telemetry block on disk and one in an image read "telemetry block in
// 2 files", not the same phrase twice.
type factKind struct {
	prefix string // "sentinel in "
	noun   string // "job log"
}

func kindOf(f model.Finding) factKind {
	switch {
	case strings.Contains(f.ID, "sentinel"):
		return factKind{"sentinel in ", "job log"}
	case strings.Contains(f.ID, "history"):
		return factKind{"exfil call in ", "shell history"}
	case strings.Contains(f.ID, "egress"):
		return factKind{"", "egress log line"}
	case strings.Contains(f.ID, "template_version") || strings.Contains(f.ID, "cached_module"):
		return factKind{"", "template version in window"}
	case strings.Contains(f.ID, "workspace"):
		return factKind{"", "workspace build"}
	case strings.Contains(f.ID, "payload"):
		return factKind{"harvester in ", "file"}
	case strings.Contains(f.ID, "telemetry"):
		return factKind{"telemetry block in ", "file"}
	case strings.Contains(f.ID, "module_indicator"):
		return factKind{"indicator in ", "module file"}
	case strings.Contains(f.ID, "script_name"):
		return factKind{"harvester-named ", "file"}
	default:
		return factKind{"", "hit"}
	}
}

// facts are the telegraph lines under the verdict: what was proven, in the
// vocabulary of the exposure paths.
func facts(rep *model.Report) []string {
	type bucket struct {
		order []factKind
		count map[factKind]int
	}
	newBucket := func() *bucket { return &bucket{count: map[factKind]int{}} }
	executed, egress, pulled, present, weak := newBucket(), newBucket(), newBucket(), newBucket(), newBucket()
	put := func(b *bucket, f model.Finding) {
		k := kindOf(f)
		if _, ok := b.count[k]; !ok {
			b.order = append(b.order, k)
		}
		b.count[k] += len(f.Evidence)
	}
	for _, f := range rep.Findings {
		switch {
		case f.Severity == model.SevLow:
			put(weak, f)
		case f.Severity < model.SevMedium:
		case f.Path == model.PathEgress:
			put(egress, f)
		case f.Path == model.PathExecuted:
			put(executed, f)
		case f.Path == model.PathTemplateImport || f.Path == model.PathWorkspaceBuild:
			put(pulled, f)
		case f.Path == model.PathPresent:
			put(present, f)
		}
	}
	render := func(b *bucket) []string {
		var parts []string
		for _, k := range b.order {
			parts = append(parts, k.prefix+engine.Plural(b.count[k], k.noun))
		}
		return parts
	}
	var lines []string
	add := func(label string, b *bucket) {
		if parts := render(b); len(parts) > 0 {
			lines = append(lines, fmt.Sprintf("%-10s %s", label, strings.Join(parts, " · ")))
		}
	}
	add("Executed", executed)
	add("Egress", egress)
	add("Pulled", pulled)
	add("Present", present)

	ran, notChecked := tierNames(rep)
	switch rep.Verdict {
	case model.VerdictCompromised:
		lines = append(lines, "The harvester ran, or data reached the exfil endpoint. Rotate now -- see ROTATE.")
	case model.VerdictExposed:
		lines = append(lines, "The tampered module was pulled or is present. No proof yet that it ran; treat it as if it did.")
	case model.VerdictIndeterminate:
		add("Weak", weak)
		var gaps []string
		for _, t := range rep.Tiers {
			if t.Status == model.TierSkipped && t.MaterialGap {
				gaps = append(gaps, t.Name+" ("+t.Reason+")")
			}
		}
		switch {
		case len(ran) == 0:
			lines = append(lines, "No tier ran. Nothing was checked -- see NEXT.")
		case len(gaps) > 0:
			lines = append(lines, "Nothing found, but the deployment itself was not asked: "+strings.Join(gaps, ", ")+". Without that view there is no answer -- see NEXT.")
		case len(weak.order) > 0:
			lines = append(lines, "Only a weak signal: a file named like the harvester whose hash matches no published variant -- see NEXT.")
		default:
			lines = append(lines, "Nothing found, but parts of the evidence could not be read -- see BLIND SPOTS and NEXT.")
		}
	default:
		lines = append(lines, "No indicator found by: "+strings.Join(ran, ", ")+".")
		if len(notChecked) > 0 {
			lines = append(lines, "Not run (optional inputs absent; see COVERAGE): "+strings.Join(notChecked, ", ")+".")
		}
	}
	return lines
}

func tierNames(rep *model.Report) (ran, skipped []string) {
	for _, t := range rep.Tiers {
		if t.Status == model.TierRan {
			ran = append(ran, t.Name)
		} else {
			skipped = append(skipped, t.Name)
		}
	}
	return ran, skipped
}

// rotateScope is what the findings actually implicate, derived per finding from
// WHERE it came from -- not from the union of path tags. A hash match on a
// laptop is not a coderd compromise, and the report must not read like one.
type rotateScope struct {
	provisioner bool // a Coder job ran the module: deploy/db findings, or the sentinel in exported provisioner output
	owners      bool // a workspace build was involved: owner tokens passed through the provisioner
	host        bool // the payload or its traces are on a scanned host / image: that host's own secrets
	egress      bool // traffic to the exfil endpoint was seen; the source host is whatever made it
}

func scopeOf(rep *model.Report) rotateScope {
	var sc rotateScope
	for _, f := range rep.Findings {
		if f.Severity < model.SevMedium {
			continue
		}
		switch f.Detector {
		case "deploy", "db":
			sc.provisioner = true
			if f.Path == model.PathWorkspaceBuild || strings.Contains(f.ID, "build") {
				sc.owners = true
			}
			// db query 3 mixes job types; a workspace_build job in its rows means owners.
			for _, e := range f.Evidence {
				if strings.HasPrefix(e.Locator, "workspace_build") {
					sc.owners = true
					break
				}
			}
		case "fs", "image":
			sc.host = true
		case "logs":
			if f.Path == model.PathEgress {
				sc.egress = true
			} else {
				sc.provisioner = true // sentinel in exported provisioner output
			}
		}
	}
	return sc
}

// rotate is the point of the report. It renders from what the findings implicate,
// so the reader is told what to rotate for THEIR situation rather than handed the
// whole advisory. Over-rotating is safer than under-rotating, but a laptop hash
// match must not read like a coderd compromise.
func rotate(w io.Writer, rep *model.Report, s Style) {
	if rep.Verdict != model.VerdictExposed && rep.Verdict != model.VerdictCompromised {
		return
	}
	sc := scopeOf(rep)
	fmt.Fprintln(w, s.c(red+bold, "ROTATE")+s.c(dim, "   treat every credential below as in the attacker's hands"))
	row := func(label string, items ...string) {
		fmt.Fprintf(w, "  %s\n", s.c(red, label))
		for _, it := range items {
			fmt.Fprintf(w, "    - %s\n", it)
		}
	}
	if sc.provisioner {
		row("Provisioner environment -- a Coder job pulled or ran the module",
			"cloud provider keys: AWS_ACCESS_KEY_ID/_SECRET, GOOGLE_APPLICATION_CREDENTIALS, ARM_CLIENT_ID/_SECRET",
			"AI-tooling keys: ANTHROPIC_API_KEY, OPENAI_API_KEY and any other model-provider key",
			"CI/CD and container-registry credentials, Terraform variables, internal service tokens",
			"if the provisioner runs inside coderd: the Coder database password and configuration")
	}
	if sc.owners {
		row("Per affected workspace owner -- a workspace build was involved",
			"OIDC token, workspace SSH key, external-auth tokens for GitHub / GitLab / Bitbucket (single-use, but enough)",
			"anything the workspace template injects as env or files")
	}
	if sc.host {
		row("On the host / image where it was found",
			"everything in environment variables, ~/.aws, ~/.config/gcloud, ~/.azure, ~/.kube, ~/.docker, ~/.npmrc, .env files, and shell history",
			"if that host is a provisioner, also the provisioner environment above; if it is a workspace, also its owner's tokens")
	}
	if sc.egress {
		row("Whatever made the connection in the egress log",
			"identify the source address: a provisioner means the provisioner environment; a workspace means its owner's tokens; a laptop means everything on it")
	}
	fmt.Fprintln(w)
}

// remediate belongs to EXPOSED / COMPROMISED only. Telling someone whose scan
// found nothing to purge their database is the wrong next action; INDETERMINATE
// gets NEXT instead.
func remediate(w io.Writer, rep *model.Report, s Style) {
	if rep.Verdict != model.VerdictExposed && rep.Verdict != model.VerdictCompromised {
		return
	}
	fmt.Fprintln(w, s.c(bold, "REMEDIATE"))
	steps := []string{
		"Purge poisoned cached modules: `leakpatrol db --purge` prints Coder's transaction; run it against the Coder database yourself, after recording the query 01-03 output.",
		"Clear on-disk Terraform module caches on every provisioner host/pod, or recycle the pods.",
		"Upgrade to a patched build: 2.37.0, 2.36.4, 2.35.7 or 2.34.9. This stops future pulls; it does not undo a past one.",
		"Search egress logs (firewall, proxy, DNS, VPC flow) from 2026-08-31 07:35 UTC onward for the exfil endpoint: `leakpatrol logs <export>`.",
	}
	for _, st := range steps {
		fmt.Fprintf(w, "  - %s\n", wrap(st, 92, "    "))
	}
	fmt.Fprintln(w)
}

// next is the INDETERMINATE section: the specific thing that would turn this
// report into an answer. Preflight already knows it; the report repeats it so
// the operator does not have to run a second command to learn what to do.
func next(w io.Writer, rep *model.Report, s Style) {
	if rep.Verdict != model.VerdictIndeterminate {
		return
	}
	var steps []string
	for _, t := range rep.Tiers {
		if t.Status != model.TierSkipped || !t.MaterialGap {
			continue
		}
		switch t.Name {
		case "deploy":
			steps = append(steps, "Ask the deployment: `coder login <url>` (or --server URL with CODER_SESSION_TOKEN set), then re-run. Drop --offline.")
		default:
			steps = append(steps, "Run the "+t.Name+" tier: "+t.Reason)
		}
	}
	ran := 0
	for _, t := range rep.Tiers {
		if t.Status == model.TierRan {
			ran++
		}
	}
	if ran == 0 && len(steps) == 0 {
		steps = append(steps, "Nothing ran. Give this command its input (see `leakpatrol --help`) or run `leakpatrol preflight`.")
	}
	material := 0
	for _, e := range rep.Errors {
		if e.Material {
			material++
		}
	}
	if material > 0 {
		steps = append(steps, fmt.Sprintf("Fix or accept the %s under BLIND SPOTS (re-run with the access they need), then re-run.", engine.Plural(material, "material read failure")))
	}
	for _, f := range rep.Findings {
		if f.Severity == model.SevLow {
			steps = append(steps, "Inspect the harvester-named file(s) under FINDINGS by hand; compare their SHA-256 with `leakpatrol iocs`.")
			break
		}
	}
	if len(steps) == 0 {
		return
	}
	fmt.Fprintln(w, s.c(bold, "NEXT"))
	for _, st := range steps {
		fmt.Fprintf(w, "  - %s\n", wrap(st, 92, "    "))
	}
	fmt.Fprintln(w)
}

func findings(w io.Writer, rep *model.Report, s Style) {
	if len(rep.Findings) == 0 {
		return
	}
	fmt.Fprintln(w, s.c(bold, "FINDINGS"))
	for _, f := range rep.Findings {
		fmt.Fprintf(w, "  %s  %s\n", sevLabel(f.Severity, s), f.Title)
		if f.Path != "" {
			fmt.Fprintf(w, "    %s\n", s.c(dim, "path: "+string(f.Path)))
		}
		if f.Detail != "" && (s.Verbose || f.Severity >= model.SevMedium) {
			fmt.Fprintf(w, "    %s\n", s.c(dim, wrap(f.Detail, 88, "    ")))
		}
		shown, omitted := f.Evidence, 0
		if !s.Verbose && len(shown) > maxRows {
			shown, omitted = shown[:maxRows], len(shown)-maxRows
		}
		var rows [][]string
		for _, e := range shown {
			rows = append(rows, []string{s.c(cyan, where(e)), e.Locator, s.c(dim, e.Note), s.c(dim, when(e.At))})
		}
		writeTable(w, "    ", rows)
		if omitted > 0 {
			fmt.Fprintf(w, "    %s\n", s.c(dim, fmt.Sprintf("... and %d more (--verbose for all, --json for the record)", omitted)))
		}
		fmt.Fprintln(w)
	}
}

func where(e model.Evidence) string {
	if e.Path != "" {
		return e.Path
	}
	if e.SourceLine > 0 {
		return fmt.Sprintf("%s:%d", e.Source, e.SourceLine)
	}
	return e.Source
}

func when(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func coverage(w io.Writer, rep *model.Report, s Style) {
	fmt.Fprintln(w, s.c(bold, "COVERAGE"))
	var rows [][]string
	for _, t := range rep.Tiers {
		switch {
		case t.Status == model.TierRan:
			rows = append(rows, []string{s.c(green, "ran"), t.Name, t.Summary, s.c(dim, t.Duration)})
		case t.MaterialGap:
			rows = append(rows, []string{s.c(yellow, "skipped"), t.Name, s.c(yellow, t.Reason+" -- verdict degraded"), ""})
		default:
			rows = append(rows, []string{s.c(dim, "skipped"), t.Name, s.c(dim, t.Reason), ""})
		}
	}
	writeTable(w, "  ", rows)
	fmt.Fprintf(w, "  %s\n\n", s.c(dim, fmt.Sprintf("window judged: %s -> %s", when(rep.Window.Start), when(rep.Window.End))))
}

func blindSpots(w io.Writer, rep *model.Report, s Style) {
	if len(rep.Errors) == 0 {
		return
	}
	fmt.Fprintln(w, s.c(bold, "BLIND SPOTS")+s.c(dim, "   what could not be read"))
	shown, omitted := rep.Errors, 0
	if !s.Verbose && len(shown) > maxRows {
		shown, omitted = shown[:maxRows], len(shown)-maxRows
	}
	for _, e := range shown {
		mark := s.c(yellow, "material")
		if !e.Material {
			mark = s.c(dim, "minor")
		}
		loc := e.Path
		if loc == "" {
			loc = e.Detector
		}
		fmt.Fprintf(w, "  %s  %s  %s\n", mark, loc, s.c(dim, e.Message))
	}
	if omitted > 0 {
		fmt.Fprintf(w, "  %s\n", s.c(dim, fmt.Sprintf("... and %d more (--verbose)", omitted)))
	}
	fmt.Fprintln(w)
}

func limitations(w io.Writer, rep *model.Report, s Style) {
	if len(rep.Limitations) == 0 {
		return
	}
	fmt.Fprintln(w, s.c(bold, "LIMITATIONS"))
	for _, l := range rep.Limitations {
		fmt.Fprintf(w, "  - %s\n", s.c(dim, wrap(l, 90, "    ")))
	}
	fmt.Fprintln(w)
}

func footer(w io.Writer, rep *model.Report, s Style) {
	fmt.Fprintf(w, "%s %s  (%s/%s)  %s  scanned in %s\n",
		s.c(dim, "leakpatrol"), s.c(dim, rep.Tool.Version), rep.Host.GOOS, rep.Host.GOARCH,
		s.c(dim, rep.Tool.Author), rep.Duration)
}

func sevLabel(sev model.Severity, s Style) string {
	name := strings.ToUpper(sev.String())
	switch sev {
	case model.SevCritical:
		return s.c(red+bold, name)
	case model.SevHigh:
		return s.c(red, name)
	case model.SevMedium:
		return s.c(yellow, name)
	}
	return s.c(dim, name)
}

// wrap breaks text at width, indenting continuation lines.
func wrap(text string, width int, indent string) string {
	words := strings.Fields(text)
	var b strings.Builder
	line := 0
	for i, wd := range words {
		n := utf8.RuneCountInString(wd)
		if line > 0 && line+1+n > width {
			b.WriteString("\n" + indent)
			line = 0
		} else if i > 0 {
			b.WriteByte(' ')
			line++
		}
		b.WriteString(wd)
		line += n
	}
	return b.String()
}

// visibleWidth returns the display width of s after stripping SGR sequences.
func visibleWidth(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == ';') {
				j++
			}
			if j < len(s) && s[j] == 'm' {
				i = j + 1
				continue
			}
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		if size == 0 {
			break
		}
		n++
		i += size
	}
	return n
}

// writeTable writes rows as a colour-safe fixed-width table.
func writeTable(w io.Writer, indent string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	cols := 0
	for _, r := range rows {
		if len(r) > cols {
			cols = len(r)
		}
	}
	widths := make([]int, cols)
	for _, r := range rows {
		for i, c := range r {
			if n := visibleWidth(c); n > widths[i] {
				widths[i] = n
			}
		}
	}
	for _, r := range rows {
		var b strings.Builder
		b.WriteString(indent)
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(r) {
				cell = r[i]
			}
			b.WriteString(cell)
			if i < cols-1 {
				gap := widths[i] - visibleWidth(cell) + 2
				b.WriteString(strings.Repeat(" ", gap))
			}
		}
		// Empty trailing cells would otherwise leave padding after the last visible
		// column; a pasted report should not carry trailing whitespace.
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
}
