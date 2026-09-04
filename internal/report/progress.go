// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/optimuslabs-io/leakpatrol/internal/engine"
)

// Progress prints, live, what the scan is looking for and what it found.
//
// A verdict is only worth the list of things that were checked to reach it, and
// -- for this incident above all -- the list of things that were NOT checked. A
// skipped db tier is the difference between "nothing in the cache" and "nobody
// looked in the cache". The narration states both, every run, out loud.
//
// It writes to stderr. Nothing but the report goes to stdout.
type Progress struct {
	w    io.Writer
	s    Style
	mu   sync.Mutex
	n    int
	open string
}

func NewProgress(w io.Writer, s Style) *Progress { return &Progress{w: w, s: s} }

// Splash plays the animated logo. UX personality, stderr only; the caller gates
// it on a colour TTY.
func (p *Progress) Splash() { animateLogo(p.w, p.s) }

// Header names what is being scanned, before the first check.
func (p *Progress) Header(what string) {
	fmt.Fprintf(p.w, "%s %s\n\n", p.s.c(bold, "leakpatrol"), p.s.c(dim, what))
}

func (p *Progress) Checking(tier, what string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	p.writeCheckingLocked(tier, what)
	if p.s.Color {
		p.open = tier
	}
}

func (p *Progress) Pulse(tier, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.s.Color || p.open != tier || status == "" {
		return
	}
	fmt.Fprint(p.w, "\033[1A\033[2K\r")
	p.writeCheckingLocked(tier, status)
}

// Checked prints what a tier found. A tier that found nothing says so out loud:
// a silent line is indistinguishable from a tier that died. The mark and colour
// follow the outcome -- green is reserved for a genuine empty result, because a
// reader who only watches this stream must not see a row of green checks over a
// COMPROMISED verdict or a tier that failed to read anything.
func (p *Progress) Checked(tier, summary string, took time.Duration, outcome engine.Outcome) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.open = ""
	if summary == "" {
		summary = "nothing found"
	}
	var mark string
	switch outcome {
	case engine.OutcomeHits:
		mark = p.s.c(red+bold, "!")
		summary = p.s.c(red, summary)
	case engine.OutcomeFailed:
		mark = p.s.c(yellow+bold, "✗")
		summary = p.s.c(yellow, summary)
	case engine.OutcomeWeak:
		mark = p.s.c(yellow, "?")
	default:
		mark = p.s.c(green, "✓")
	}
	fmt.Fprintf(p.w, "    %s %-13s %s %s\n", mark, p.s.c(dim, tier), summary, p.s.c(dim, "("+fmtDur(took)+")"))
}

// Skipped prints an unchecked tier. Dim, not the exposure colour: most skips are
// optional inputs the operator simply did not have (an image tar, a flow-log
// export), and the report's COVERAGE table is where the one material skip -- the
// deployment itself -- is called out.
func (p *Progress) Skipped(tier, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	p.open = ""
	fmt.Fprintf(p.w, "  %s %-13s %s\n", p.s.c(dim, "○"), tier, p.s.c(dim, "skipped: "+reason))
}

func (p *Progress) Done(total time.Duration) {
	fmt.Fprintf(p.w, "\n  %s\n\n", p.s.c(dim, fmt.Sprintf("%d tiers in %s", p.n, fmtDur(total))))
}

func (p *Progress) writeCheckingLocked(tier, what string) {
	fmt.Fprintf(p.w, "  %s %-13s %s\n", p.s.c(cyan, "→"), tier, p.s.c(dim, what))
}

func fmtDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return "<1ms"
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}
