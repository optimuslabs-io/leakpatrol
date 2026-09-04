// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package version reports whether a Coder build is one of the patched releases.
// It is informational: the advisory scopes exposure by ACTIVITY in the window, not
// by version, and a patched server does not undo a pull that already happened.
package version

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

// Patched are the builds the advisory names. Anything at or above each line's
// patch level, or on a newer minor, is patched.
var Patched = []string{"2.37.0", "2.36.4", "2.35.7", "2.34.9"}

var semver = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// Parse pulls the first semver out of free text ("Coder v2.36.3+abc123 ...").
func Parse(s string) (major, minor, patch int, ok bool) {
	m := semver.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	patch, _ = strconv.Atoi(m[3])
	return major, minor, patch, true
}

// IsPatched decides against the advisory's list. Minors older than the oldest
// patched line (2.34) have no patched build at all.
func IsPatched(major, minor, patch int) bool {
	if major > 2 {
		return true
	}
	if major < 2 {
		return false
	}
	switch {
	case minor >= 37:
		return true
	case minor == 36:
		return patch >= 4
	case minor == 35:
		return patch >= 7
	case minor == 34:
		return patch >= 9
	}
	return false
}

// Finding builds the informational finding for a version string from a named
// source ("coder CLI", "server /api/v2/buildinfo").
func Finding(detector, source, raw string) (model.Finding, bool) {
	major, minor, patch, ok := Parse(raw)
	if !ok {
		return model.Finding{}, false
	}
	v := strconv.Itoa(major) + "." + strconv.Itoa(minor) + "." + strconv.Itoa(patch)
	f := model.Finding{Detector: detector, Severity: model.SevInfo}
	if IsPatched(major, minor, patch) {
		f.ID = detector + ".patched"
		f.Title = source + " is Coder " + v + " -- a patched build"
		f.Detail = "Patched builds stop serving from the hijacked pool; they do not clear a module cache poisoned during the window. Check the db/deploy tiers."
	} else {
		f.ID = detector + ".unpatched"
		f.Title = source + " is Coder " + v + " -- NOT a patched build (" + strings.Join(Patched, ", ") + ")"
		f.Detail = "Upgrade after containment. Exposure is decided by activity in the window, not by this number."
	}
	f.Evidence = []model.Evidence{{Path: source, Note: "version " + v}}
	return f, true
}

type Detector struct{}

func New() *Detector { return &Detector{} }

// The tier is named coder-version, not version: `leakpatrol version` is the
// tool's own version, and a scan-shaped CLEAN under that word was read as a scan.
func (*Detector) Name() string { return "coder-version" }

func (*Detector) Describe() string {
	return "the coder CLI's version against the patched builds (the deploy tier reads the server's)"
}

func (*Detector) Ready(*engine.Env) string {
	if _, err := exec.LookPath("coder"); err != nil {
		return "coder CLI not on PATH (informational only; the deploy tier reads the server's version)"
	}
	return ""
}

// Material: informational tier; never affects the verdict.
func (*Detector) Material() bool { return false }

func (d *Detector) Run(ctx context.Context, _ *engine.Env) engine.Result {
	var res engine.Result
	// `coder version` is the one argument ever passed; it prints and exits.
	out, err := exec.CommandContext(ctx, "coder", "version").Output()
	if err != nil {
		res.Errors = append(res.Errors, model.ScanError{Detector: d.Name(), Kind: "io", Message: "coder version: " + err.Error(), Material: false})
		res.Summary = "coder version failed"
		return res
	}
	f, ok := Finding(d.Name(), "coder CLI", string(out))
	if !ok {
		res.Summary = "could not parse coder version output"
		return res
	}
	res.Findings = append(res.Findings, f)
	res.Summary = strings.TrimPrefix(f.Title, "coder CLI is ")
	res.Limitations = append(res.Limitations, "The version tier reads the coder CLI on this machine, which may differ from the server. Exposure is activity-scoped; a patched build is containment, not exoneration.")
	return res
}
