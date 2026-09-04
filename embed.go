// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package leakpatrol exposes the repository's plain-text assets that the
// binary embeds. It lives at the module root so the SQL stays where an operator
// who never builds anything expects to find it: ./sql/.
package leakpatrol

import "embed"

// SQL holds Coder's verbatim advisory queries. 03 carries a {{SENTINEL}}
// placeholder in place of the log-search literal, substituted at runtime, so the
// binary never contains the indicator it hunts for (see internal/scan/markers.go).
//
//go:embed sql/*.sql
var SQL embed.FS
