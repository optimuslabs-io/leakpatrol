// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"encoding/json"
	"io"

	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

// JSON writes the machine-readable report. Nothing but JSON goes to this writer:
// every diagnostic is written to stderr, so `leakpatrol --json | jq` always works.
func JSON(w io.Writer, rep *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	// Empty slices rather than nulls: a consumer should be able to range over
	// .findings without a nil check.
	if rep.Findings == nil {
		rep.Findings = []model.Finding{}
	}
	if rep.Errors == nil {
		rep.Errors = []model.ScanError{}
	}
	if rep.Tiers == nil {
		rep.Tiers = []model.Tier{}
	}
	if rep.Paths == nil {
		rep.Paths = []model.Path{}
	}
	if rep.Limitations == nil {
		rep.Limitations = []string{}
	}
	return enc.Encode(rep)
}

// RawJSON writes any value with the same formatting rules as JSON.
func RawJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
