// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"bytes"
	"io"
	"path"
	"regexp"
	"strings"
)

// Hit is one marker seen on one line. It carries the LINE NUMBER and which marker
// matched -- never the line's text. The text of a matching line in a shell history
// is, by construction, the exfil command and whatever credential it carried.
type Hit struct {
	Marker Marker
	Line   int
}

// maxLine bounds a single line. Minified JSON logs and flow-log exports can put a
// whole day on one line; the scanner must not fail on them, and must not allocate
// without bound either. Lines longer than this are scanned in chunks, so a marker
// that straddles a chunk boundary is the one blind spot -- stated in Limitations.
const maxLine = 4 << 20

// ScanLines reads r line by line and reports every marker hit. It is used for
// shell histories, cached module files, egress logs and provisioner logs alike:
// the only thing that differs between those is what a hit MEANS, which is the
// detector's call, not the matcher's.
//
// Each line is lower-cased once and matched against the lower-case markers, so
// header-name case and a `www.` prefix do not matter. onHit is called per marker
// per line; return false to stop early (a caller that only needs to know whether
// there is at least one hit does not need to read a 10 GB log to the end).
func ScanLines(r io.Reader, markers []Marker, onHit func(Hit) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	line := 0
	// One scratch buffer reused across every line instead of a fresh bytes.ToLower
	// allocation per candidate line. The markers are all ASCII, so ASCII-only
	// lowercasing is enough: a non-ASCII byte can never be part of an ASCII needle,
	// so folding only A-Z yields identical match results with no allocation.
	var low []byte
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if !mayContainMarker(b) {
			continue
		}
		low = append(low[:0], b...)
		lowerASCII(low)
		for _, m := range markers {
			if bytes.Contains(low, m.Bytes()) {
				if !onHit(Hit{Marker: m, Line: line}) {
					return nil
				}
			}
		}
	}
	err := sc.Err()
	if err == bufio.ErrTooLong {
		// The scanner cannot resume past an over-long line, and the lines after it
		// are unread. Surface that as a distinct, material error rather than a
		// generic failure: the fix (split the export) is the reader's to make, and a
		// verdict that silently ignored the tail of a log must not read as CLEAN.
		return errLineTooLong
	}
	return err
}

// mayContainMarker is a cheap prefilter: every marker contains one of these
// bytes, so a line with none of them cannot match and skips the lower-casing.
func mayContainMarker(b []byte) bool {
	return bytes.IndexByte(b, '.') >= 0 || bytes.IndexByte(b, '/') >= 0 || bytes.IndexByte(b, '-') >= 0
}

// lowerASCII folds A-Z to a-z in place. It leaves every other byte untouched,
// including UTF-8 multibyte sequences, which is exactly what marker matching needs:
// the markers are ASCII, so no non-ASCII byte can be part of a needle.
func lowerASCII(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
}

type scanErr string

func (e scanErr) Error() string { return string(e) }

// errLineTooLong is returned when an input has a line over maxLine bytes. The
// realistic case is a single-line JSON export; `jq -c '.[]'` splits it.
const errLineTooLong = scanErr("a line exceeds the 4 MiB scanner limit; split the input (e.g. jq -c '.[]') and re-run")

// IsLineTooLong reports whether err is the over-long line condition.
func IsLineTooLong(err error) bool { return err == errLineTooLong }

// IsText decides whether a buffer is worth line-scanning. A NUL in the first
// 8 KiB means binary: the harvester's outputs and inputs are shell scripts, HCL,
// histories and logs, all text, and scanning an executable for a domain name
// finds only other scanners.
func IsText(head []byte) bool {
	if len(head) > 8192 {
		head = head[:8192]
	}
	return bytes.IndexByte(head, 0) < 0
}

// IsScriptName reports whether a basename is one of the harvester filenames.
// Case-insensitive: a Windows provisioner does not care about case either.
func IsScriptName(name string) bool {
	low := strings.ToLower(path.Base(strings.ReplaceAll(name, "\\", "/")))
	for _, s := range ScriptNames() {
		if low == s {
			return true
		}
	}
	return false
}

// IsTerraformName reports whether a file is Terraform configuration, in either
// syntax. Only these are searched for the telemetry data block.
func IsTerraformName(name string) bool {
	low := strings.ToLower(name)
	return strings.HasSuffix(low, ".tf") || strings.HasSuffix(low, ".tf.json")
}

// telemetryHCL matches the block the tampered modules added:
//
//	data "external" "telemetry" {
//
// with any whitespace between tokens. telemetryJSON is the same resource in
// .tf.json form. Neither pattern is the dotted sentinel string the log search
// uses, so a .tf file is judged on structure, not on a substring.
var (
	telemetryHCL  = regexp.MustCompile(`(?i)\bdata\s+"external"\s+"telemetry"\s*\{`)
	telemetryJSON = regexp.MustCompile(`(?is)"external"\s*:\s*\{\s*"telemetry"\s*:`)
)

// FindTelemetryBlock reports the 1-based line of the first telemetry data block in
// a Terraform file, or 0.
func FindTelemetryBlock(name string, content []byte) int {
	var loc []int
	if strings.HasSuffix(strings.ToLower(name), ".json") {
		loc = telemetryJSON.FindIndex(content)
	} else {
		loc = telemetryHCL.FindIndex(content)
	}
	if loc == nil {
		return 0
	}
	return 1 + bytes.Count(content[:loc[0]], []byte{'\n'})
}
