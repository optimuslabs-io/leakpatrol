// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo carries build-time identity stamped in via -ldflags -X.
package buildinfo

import "runtime"

// Version is the tool's own release version. It is a real number rather than "dev"
// so that a report pasted into an incident ticket, or compared across a fleet of
// provisioners, says which build produced it. The Makefile overrides this from
// `git describe` when a tag exists.
var (
	Version = "0.1.0"
	Commit  = "none"
	Date    = "unknown"
)

// GoVersion is reported so a user can reproduce the build.
func GoVersion() string { return runtime.Version() }

// Attribution is printed by --version, under the logo, and carried in --json. It
// is a single constant so every surface says the same thing.
const Attribution = "Optimus Labs · Civilizations research team"

// Advisory is the vendor advisory every indicator in this tool traces back to.
const Advisory = "GHSA-vx42-ghc9-gw65"

// Repo is the canonical source location, for the footer and the README pointer.
const Repo = "github.com/optimuslabs-io/leakpatrol"
