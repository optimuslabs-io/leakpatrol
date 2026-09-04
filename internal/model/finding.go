// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"time"
)

type Severity int

const (
	SevInfo     Severity = iota // context, not a problem
	SevLow                      // WEAK signal: a filename match alone
	SevMedium                   // exposure: a module was pulled in the window, no proof it ran
	SevHigh                     // strong IoC: the tampered module or payload is present on disk / in an image
	SevCritical                 // proof of execution or egress: the sentinel in a job log, an exfil hit in egress logs, the harvester in shell history
)

var sevNames = map[Severity]string{
	SevInfo:     "info",
	SevLow:      "low",
	SevMedium:   "medium",
	SevHigh:     "high",
	SevCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := sevNames[s]; ok {
		return n
	}
	return "unknown"
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Path names WHICH exposure path a finding implicates, which is what decides what
// the operator has to rotate. The advisory scopes leakage by activity, not version:
// a template import leaks the provisioner's own environment; a workspace build
// additionally leaks the owner's tokens. The report's ROTATE section is driven off
// these tags, so a finding without one cannot tell the reader what to do.
type Path string

const (
	// PathTemplateImport: a template create/update/dry-run pulled the module. The
	// provisioner's environment leaked -- cloud, AI-tooling and CI/CD keys, and the
	// coderd database credentials if the provisioner runs in-process.
	PathTemplateImport Path = "template-import"
	// PathWorkspaceBuild: a workspace build pulled (or reused) the module. Everything
	// above PLUS the workspace owner's OIDC token, SSH key and external-auth tokens.
	PathWorkspaceBuild Path = "workspace-build"
	// PathPresent: the tampered module or payload is on disk or in an image. It was
	// delivered; whether it ran is what the other tags establish.
	PathPresent Path = "present"
	// PathExecuted: the harvester ran -- the Terraform sentinel in a job log, or the
	// exfil call in a shell history.
	PathExecuted Path = "executed"
	// PathEgress: traffic to the exfil endpoint was observed. Data left.
	PathEgress Path = "egress"
)

// Evidence points at what was found. It has no field capable of carrying file
// contents, and that is the point: the harvester this tool hunts for stole
// credentials out of files and environments, and a report about that must never
// reproduce them. Every field below is a LOCATION, an IDENTIFIER, a HASH, a
// TIMESTAMP, or tool-authored prose. "The log line said X" fails that test; "the
// sentinel appeared at fw.log:412" passes.
type Evidence struct {
	Path      string `json:"path"`                 // a file path, an image path, or a Coder object (template/version, workspace)
	Locator   string `json:"locator,omitempty"`    // "line:412", "layer:<sha>", a job id, a module file id
	Note      string `json:"note,omitempty"`       // tool-authored prose, never file-derived
	SHA256    string `json:"sha256,omitempty"`     // only for hash-matched payloads
	SizeBytes int64  `json:"size_bytes,omitempty"` // metadata only

	// Source and SourceLine cite the artifact this evidence was READ FROM, so a
	// reader can check the claim by hand. The line NUMBER is evidence; the line's
	// TEXT is not, and must never be put here.
	Source     string `json:"source,omitempty"`
	SourceLine int    `json:"source_line,omitempty"`

	// At is the timestamp the evidence carries (a job's start, a cache entry's
	// creation) -- what places it inside or outside the advisory window.
	At time.Time `json:"at,omitempty"`
}

type Finding struct {
	ID       string     `json:"id"` // stable slug, e.g. "deploy.sentinel_in_job_log"
	Detector string     `json:"detector"`
	Severity Severity   `json:"severity"`
	Path     Path       `json:"path,omitempty"`
	Title    string     `json:"title"`
	Detail   string     `json:"detail,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// Executed reports whether this finding is proof the harvester RAN or data LEFT,
// as opposed to the module merely having been pulled or being present. It is
// tag-based rather than severity-based, and it is the one thing that separates
// COMPROMISED from EXPOSED.
func (f Finding) Executed() bool {
	return f.Path == PathExecuted || f.Path == PathEgress
}

// ScanError is a non-fatal failure.
//
// A MATERIAL error is one that could have hidden an indicator: a directory we
// could not enter, an API page we could not fetch, a tar we could not read to
// the end. Material errors set Report.Degraded, which forbids a CLEAN verdict --
// a scanner that was blocked from half the evidence must never say it found nothing.
type ScanError struct {
	Detector string `json:"detector"`
	Kind     string `json:"kind"` // "permission", "parse", "timeout", "panic", "io", "http"
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
	Material bool   `json:"material"`
}
