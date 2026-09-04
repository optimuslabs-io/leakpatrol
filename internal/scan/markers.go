// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package scan holds the indicators this tool hunts for and the matchers that
// find them in bytes. Nothing here touches the filesystem or the network.
package scan

// Indicators of compromise, transcribed from GHSA-vx42-ghc9-gw65.
//
// THEY ARE STORED REVERSED AND FLIPPED AT INIT, ON PURPOSE. No non-test source
// file in this module may contain any marker as a readable literal.
//
// A scanner that stores the indicator it hunts for CONTAINS that indicator, so it
// finds itself: run `leakpatrol fs` over a directory holding the binary and a
// naive build reports its own executable as carrying the exfil domain. Splitting a
// literal into fragments is not enough either -- the Go linker packs string
// constants contiguously into .rodata, so adjacent fragments can spell the marker
// back out. Storing each marker reversed means no substring of any marker exists
// in the binary in reading order, whatever the linker does with the layout.
// TestCompiledBinaryDoesNotContainItsOwnMarkers builds the real binary and greps it.
//
// Every marker is stored lower-case: the text matcher lower-cases each line once
// and compares against these, so `X-CLI-Token` and `x-cli-token` both hit and the
// domain matches with or without the `www.` prefix.
var (
	// "coder-infra.com" -- the lookalike exfil domain, registered 2026-08-28.
	MarkerDomain = rev("moc.arfni-redoc")
	// "199.91.220.205" -- the rogue IP added to the registry.coder.com pool and
	// serving the exfil endpoint.
	MarkerIP = rev("502.022.19.991")
	// "/cli/check" -- the exfil URL path.
	MarkerPath = rev("kcehc/ilc/")
	// "x-cli-token" -- the HTTP header the harvester sent its payload under.
	MarkerHeader = rev("nekot-ilc-x")
	// "data.external.telemetry" -- the sentinel Coder's advisory tells operators to
	// search provisioner job logs for: the Terraform address of the external data
	// source that invoked the harvester.
	MarkerSentinel = rev("yrtemelet.lanretxe.atad")
	// "dlp-docker.sh" and "dlp.sh" -- the harvester scripts' filenames.
	MarkerScriptDocker = rev("hs.rekcod-pld")
	MarkerScript       = rev("hs.pld")
)

// Marker pairs a reversed-stored indicator with the prose the report uses for it
// and how strong a hit on it is. Label is tool-authored and never contains the
// marker itself, so a report line can describe a hit without repeating the IoC
// in a place that might itself be scanned later.
type Marker struct {
	Value string
	Label string
	// Egress marks the markers that prove TRAFFIC to the exfil endpoint when seen in
	// a network log, as opposed to the sentinel, which proves the module ran.
	Egress bool
	// vb is Value as bytes, precomputed once so the line scanner does not allocate a
	// fresh []byte(Value) for every marker on every candidate line (fs pass 2 scans
	// ~all files on a clean disk; that allocation dominated the hot loop). Set by
	// the cached TextMarkers below; ScanLines falls back to []byte(Value) if unset,
	// so a hand-built Marker still matches correctly.
	vb []byte
}

// Bytes returns the marker value as a byte slice, using the precomputed copy when
// present. The line matcher uses this to avoid per-line allocation.
func (m Marker) Bytes() []byte {
	if m.vb != nil {
		return m.vb
	}
	return []byte(m.Value)
}

// textMarkers is built once at package init. Sharing the slice is safe: callers
// only read it, and every field including vb is immutable after this.
var textMarkers = func() []Marker {
	ms := []Marker{
		{Value: MarkerDomain, Label: "lookalike exfil domain", Egress: true},
		{Value: MarkerIP, Label: "rogue registry / exfil IP", Egress: true},
		{Value: MarkerPath, Label: "exfil URL path", Egress: true},
		{Value: MarkerHeader, Label: "exfil HTTP header", Egress: true},
		{Value: MarkerSentinel, Label: "Terraform sentinel (harvester data source)"},
	}
	for i := range ms {
		ms[i].vb = []byte(ms[i].Value)
	}
	return ms
}()

// TextMarkers is the set the line scanner searches every text line for. It returns
// the shared, precomputed slice (built once at init), not a fresh allocation per
// call. The script filenames are deliberately NOT in it: "dlp.sh" is three letters
// and a dot, and matching it in arbitrary text would manufacture hits out of
// nothing. Filenames are matched by the filename detector, on the basename only.
func TextMarkers() []Marker { return textMarkers }

// ScriptNames are the payload filenames, matched case-insensitively on basenames.
func ScriptNames() []string { return []string{MarkerScript, MarkerScriptDocker} }

// rev reverses a string. It runs at package init, so the compiler cannot fold it
// back into the readable literal.
func rev(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
