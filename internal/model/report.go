// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package model

import "time"

// Verdict is the headline, carried in the report body and --json. It does NOT drive
// the process exit code: the exit code answers only "did leakpatrol run", never
// "what did it find" -- see ExitToolError.
type Verdict string

const (
	VerdictClean         Verdict = "CLEAN"         // every tier ran, nothing found
	VerdictIndeterminate Verdict = "INDETERMINATE" // nothing found, but a tier was skipped or the scan was degraded
	VerdictExposed       Verdict = "EXPOSED"       // the tampered module was pulled or is present; no proof it ran
	VerdictCompromised   Verdict = "COMPROMISED"   // the harvester ran, or traffic to the exfil endpoint was seen
)

// ExitToolError is the only non-zero process exit code: bad flags or an internal
// failure. A completed scan -- whatever its verdict -- exits 0.
const ExitToolError = 1

const SchemaVersion = "leakpatrol/v1"

type ToolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuiltAt   string `json:"built_at"`
	GoVersion string `json:"go_version"`
	Author    string `json:"author"`
	Advisory  string `json:"advisory"`
	Source    string `json:"source"`
}

type HostInfo struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	Home   string `json:"home"`
}

// Window is the advisory's serving window, carried in every report so a reader
// (or a later tool) knows which timestamps the in-window findings were judged
// against without consulting the source.
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Tier records whether a detector ran, and if not, why. A verdict is only worth
// the list of things that were checked to reach it, and a skipped tier is the
// most important line in that list.
type Tier struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // "ran" | "skipped"
	Reason   string `json:"reason,omitempty"`
	Summary  string `json:"summary,omitempty"`
	Duration string `json:"duration,omitempty"`
	// MaterialGap marks a skip that degrades the verdict (in `all` mode, a skipped
	// deploy tier). Every other skip is coverage information only.
	MaterialGap bool `json:"material_gap,omitempty"`
}

const (
	TierRan     = "ran"
	TierSkipped = "skipped"
)

type Report struct {
	Schema    string    `json:"schema"`
	Tool      ToolInfo  `json:"tool"`
	Host      HostInfo  `json:"host"`
	Window    Window    `json:"window"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`

	Verdict Verdict `json:"verdict"`
	// Paths lists every exposure path at least one finding implicated, worst first.
	// It is what the ROTATE section renders from.
	Paths    []Path         `json:"paths"`
	Counts   map[string]int `json:"counts"` // by severity name
	Findings []Finding      `json:"findings"`
	Tiers    []Tier         `json:"tiers"`

	Errors   []ScanError `json:"errors"`
	Degraded bool        `json:"degraded"`
	// Limitations is populated on EVERY run, including a clean one. Nobody should
	// read CLEAN without also reading what this tool structurally cannot see.
	Limitations []string `json:"limitations"`
}
