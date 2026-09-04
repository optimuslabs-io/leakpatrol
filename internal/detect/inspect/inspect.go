// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package inspect judges ONE file's name and bytes against every indicator. The fs
// tier and the image tier feed it the same way -- a name, a size, and up to
// MaxFileSize bytes -- so a harvester found on disk and a harvester found in a
// container layer are judged by identical rules.
package inspect

import (
	"bytes"
	"path"
	"strings"
	"sync"

	"github.com/optimuslabs-io/leakpatrol/internal/hostfs"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
	"github.com/optimuslabs-io/leakpatrol/internal/scan"
)

// Kind is what a match means, which is what decides its severity and path tag.
type Kind int

const (
	// KindPayload: the bytes hash to a published harvester variant. Definitive.
	KindPayload Kind = iota
	// KindTelemetry: a Terraform file declares the harvester's data source.
	KindTelemetry
	// KindHistory: an exfil indicator in a shell history -- the call was MADE here.
	KindHistory
	// KindModule: an exfil indicator inside Terraform / a module cache -- the
	// tampered module is present.
	KindModule
	// KindReference: an exfil indicator in some other text file. Real, but it could
	// be a note, a SIEM export, or another scanner's rule set; a human decides.
	KindReference
	// KindName: named like the harvester but hashes to nothing published. Weak: an
	// unpublished variant, or an unrelated script that happens to share the name.
	KindName
)

// Match is one judgement about one file. It carries locations and a hash, never
// content.
type Match struct {
	Kind   Kind
	Line   int    // first matching line for text kinds; 0 otherwise
	Label  string // tool-authored: which marker or which payload variant
	SHA256 string // for KindPayload
	Hits   int    // number of matching lines for text kinds
}

// Severity and Path for each kind. Kept here, next to the kinds, so the two
// tiers cannot drift apart in how they grade the same evidence.
func (k Kind) Severity() model.Severity {
	switch k {
	case KindHistory:
		return model.SevCritical
	case KindPayload, KindTelemetry, KindModule:
		return model.SevHigh
	case KindReference:
		return model.SevMedium
	default:
		return model.SevLow
	}
}

func (k Kind) Path() model.Path {
	if k == KindHistory {
		return model.PathExecuted
	}
	return model.PathPresent
}

// ID is the stable finding slug for a kind, prefixed by the tier name.
func (k Kind) ID(tier string) string {
	switch k {
	case KindPayload:
		return tier + ".payload_hash"
	case KindTelemetry:
		return tier + ".telemetry_block"
	case KindHistory:
		return tier + ".history_exfil"
	case KindModule:
		return tier + ".module_indicator"
	case KindReference:
		return tier + ".indicator_reference"
	default:
		return tier + ".script_name"
	}
}

func (k Kind) Title() string {
	switch k {
	case KindPayload:
		return "Harvester script present (SHA-256 matches a published variant)"
	case KindTelemetry:
		return "Terraform declares the harvester's telemetry data source"
	case KindHistory:
		return "Exfil endpoint in a shell history -- the harvester ran on this host"
	case KindModule:
		return "Exfil indicator inside Terraform / module cache"
	case KindReference:
		return "Exfil indicator in a text file (review: could be notes, an export, or another scanner's rules)"
	default:
		return "File named like the harvester but not a published variant (weak)"
	}
}

// File judges a file. content is the first min(size, cap) bytes; truncated says
// whether that is the whole file. isText is the caller's NUL-sniff classification
// (the fs tier already computed it while deciding how much to read, so passing it
// avoids a second scan.IsText over the same bytes); it equals scan.IsText(content).
// A truncated file is not hashed, because a partial digest is not evidence.
func File(name string, content []byte, truncated, isText bool) []Match {
	var out []Match
	base := path.Base(strings.ReplaceAll(name, "\\", "/"))
	isScript := scan.IsScriptName(base)

	if !truncated && len(content) > 0 {
		if p, ok := scan.MatchPayload(scan.DigestBytes(content)); ok {
			out = append(out, Match{Kind: KindPayload, Label: p.Label, SHA256: p.SHA256})
			return out // the strongest possible statement about this file; nothing to add
		}
	}

	if isText {
		if scan.IsTerraformName(base) {
			if line := scan.FindTelemetryBlock(base, content); line > 0 {
				out = append(out, Match{Kind: KindTelemetry, Line: line, Label: "telemetry data source"})
			}
		}
		if m, ok := textMatch(name, base, content); ok {
			out = append(out, m)
		}
	}

	if isScript && !hasKind(out, KindPayload) {
		out = append(out, Match{Kind: KindName, Label: "harvester filename"})
	}
	return out
}

// textMatch runs the marker scan and classifies the hit by WHERE the file lives.
func textMatch(name, base string, content []byte) (Match, bool) {
	first, hits := 0, 0
	label := ""
	_ = scan.ScanLines(bytes.NewReader(content), scan.TextMarkers(), func(h scan.Hit) bool {
		hits++
		if first == 0 {
			first, label = h.Line, h.Marker.Label
		}
		return true
	})
	if hits == 0 {
		return Match{}, false
	}
	kind := KindReference
	switch {
	case isHistory(base):
		kind = KindHistory
	case scan.IsTerraformName(base) || InKnownBadTree(name):
		kind = KindModule
	}
	return Match{Kind: kind, Line: first, Label: label, Hits: hits}, true
}

func isHistory(base string) bool {
	for _, h := range hostfs.HistoryNames() {
		if base == h {
			return true
		}
	}
	return false
}

// InKnownBadTree recognises the places Terraform puts fetched modules: the
// .terraform data dir, a plugin cache, or a Coder provisioner work directory.
// These are the locations a tampered module actually lives in, so a hit here is
// graded higher than the same string sitting in an arbitrary text file -- and
// (see EagerRead) they are read on the fast pass rather than deferred, because
// nothing outranks "look exactly where the attack lands" for cost per bit of signal.
func InKnownBadTree(name string) bool {
	p := strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
	return strings.Contains(p, "/.terraform/") ||
		strings.Contains(p, "/modules/") ||
		strings.Contains(p, "terraform.d/") ||
		strings.Contains(p, "coder-provisioner")
}

// EagerRead reports whether a file's NAME or LOCATION alone justifies reading it
// on the fast, always-run pass: the harvester's own filename, a Terraform file
// (checked for the telemetry block), a shell history, or a known module-cache
// location. Every one of these is HIGH or CRITICAL if it fires at all -- so a scan
// that gets a hit here already has its verdict, and nothing else needs reading to
// reach it. Everything NOT eager is deferred to the slower pass, which exists
// only to rule the tampered module OUT when the fast pass found nothing.
func EagerRead(name string) bool {
	base := path.Base(strings.ReplaceAll(name, "\\", "/"))
	return scan.IsScriptName(base) || scan.IsTerraformName(base) || isHistory(base) || InKnownBadTree(name)
}

func hasKind(ms []Match, k Kind) bool {
	for _, m := range ms {
		if m.Kind == k {
			return true
		}
	}
	return false
}

// Collector groups matches into one finding per kind, preserving every evidence
// row (the terminal caps what it prints; --json is the complete record). It is
// safe for concurrent Add: the fs tier reads files from a worker pool.
type Collector struct {
	Tier     string
	mu       sync.Mutex
	findings map[Kind]*model.Finding
	order    []Kind
	Files    int
	Hits     int
}

// HitCount is the concurrent-safe read of Hits for progress lines.
func (c *Collector) HitCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Hits
}

// MaxSeverity is the worst severity seen so far. The fs tier's fast pass uses
// this to decide whether the slow pass needs to run at all: once something HIGH
// or above has fired, the verdict is already set and every remaining file is
// extra location, not extra answer.
func (c *Collector) MaxSeverity() model.Severity {
	c.mu.Lock()
	defer c.mu.Unlock()
	max := model.SevInfo
	for _, f := range c.findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

func (c *Collector) Add(displayPath string, ms []Match, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.findings == nil {
		c.findings = map[Kind]*model.Finding{}
	}
	for _, m := range ms {
		f, ok := c.findings[m.Kind]
		if !ok {
			f = &model.Finding{
				ID: m.Kind.ID(c.Tier), Detector: c.Tier, Severity: m.Kind.Severity(),
				Path: m.Kind.Path(), Title: m.Kind.Title(),
			}
			c.findings[m.Kind] = f
			c.order = append(c.order, m.Kind)
		}
		ev := model.Evidence{Path: displayPath, Note: m.Label, SHA256: m.SHA256, SizeBytes: size}
		if m.Line > 0 {
			ev.Locator = "line:" + itoa(m.Line)
			if m.Hits > 1 {
				// Hits counts marker matches, not lines: one exfil command line carries
				// the domain, the path and the header at once.
				ev.Note = m.Label + " (+" + itoa(m.Hits-1) + " more indicator matches)"
			}
		}
		f.Evidence = append(f.Evidence, ev)
		c.Hits++
	}
}

func (c *Collector) Findings() []model.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []model.Finding
	for _, k := range c.order {
		f := c.findings[k]
		f.Title = f.Title + " -- " + itoa(len(f.Evidence)) + plural(len(f.Evidence), " file")
		out = append(out, *f)
	}
	return out
}

func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
