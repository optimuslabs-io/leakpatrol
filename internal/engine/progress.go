// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package engine

import "time"

// Outcome is how a tier ended, for the progress line's colour. People read the
// spinner and skip stdout, so a tier that found something or died must not look
// like a tier that came back empty.
type Outcome int

const (
	OutcomeEmpty  Outcome = iota // ran, nothing at or above MEDIUM, no material error
	OutcomeHits                  // found something (MEDIUM or above)
	OutcomeWeak                  // only weak (LOW) or informational signal
	OutcomeFailed                // a material error: the tier's answer is incomplete
)

// Progress narrates the scan while it runs.
//
// It answers a question the final report cannot: what did you LOOK for? A verdict
// of CLEAN is only worth as much as the list of things that were checked to reach
// it, and that list should not be something you have to read the source to
// discover. It also keeps a minute-long walk of a provisioner's disk from looking
// like a hang.
//
// Progress goes to stderr, never stdout: `leakpatrol --json | jq` must keep working.
type Progress interface {
	// Checking announces what a tier is about to look for, before it starts.
	Checking(tier, what string)
	// Pulse rewrites the in-flight Checking line with a live status. No-op when
	// nothing is watching. Callers must be the goroutine that called Checking.
	Pulse(tier, status string)
	// Checked reports what a tier found. summary is the tier's own one-liner;
	// outcome decides the colour.
	Checked(tier, summary string, took time.Duration, outcome Outcome)
	// Skipped records a tier that could not run, and why.
	Skipped(tier, reason string)
	// Done closes out the run.
	Done(total time.Duration)
}

// nopProgress is used when nothing is watching (--quiet, or a piped stderr).
type nopProgress struct{}

func (nopProgress) Checking(string, string)                        {}
func (nopProgress) Pulse(string, string)                           {}
func (nopProgress) Checked(string, string, time.Duration, Outcome) {}
func (nopProgress) Skipped(string, string)                         {}
func (nopProgress) Done(time.Duration)                             {}

// Pulse is a nil-safe helper for detectors.
func (e *Env) Pulse(tier, status string) {
	if e.Progress != nil {
		e.Progress.Pulse(tier, status)
	}
}
