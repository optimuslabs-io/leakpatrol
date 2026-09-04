// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package iocs renders the indicator set as JSON for SIEM import and for other
// tooling. The forward-reading strings are assembled at runtime from the
// reversed markers, so exporting them never puts them in the binary.
package iocs

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/optimuslabs-io/leakpatrol/internal/buildinfo"
	"github.com/optimuslabs-io/leakpatrol/internal/detect/version"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
	"github.com/optimuslabs-io/leakpatrol/internal/scan"
)

// Window is the advisory's serving window, UTC.
var Window = model.Window{
	Start: time.Date(2026, 8, 31, 7, 35, 0, 0, time.UTC),
	End:   time.Date(2026, 8, 31, 21, 45, 0, 0, time.UTC),
}

// VariantModules are the module names the advisory attaches to individual harvester
// builds in its hash table: one build per module, plus a "common" build.
//
// This is NOT an enumerated list of tampered modules, and the advisory does not
// publish one. A bespoke build per module is strong evidence those modules were
// served tampered; the common build is the reason the list cannot be treated as the
// scope of the incident, since it is what shipped in modules that got no bespoke
// build. Exported so an operator can prioritise, never to bound an investigation.
//
// Nothing in this tool detects on these names. Every detector matches a payload
// hash, the telemetry block, or a network indicator, none of which depend on which
// module carried the harvester.
var VariantModules = []string{"aider", "rstudio-server", "windows-rdp", "zed"}

// Techniques is the MITRE ATT&CK mapping from the Optimus Labs briefing.
var Techniques = []string{
	"T1583.001", "T1584", // acquire / compromise infrastructure
	"T1078",          // valid accounts (vendor's CDN control plane)
	"T1195.002",      // supply chain: software supply chain
	"T1553", "T1036", // subvert trust controls, masquerading (a "telemetry" data source)
	"T1059.004", // unix shell
	"T1552",     // unsecured credentials: files and environment
	"T1567.002", // exfiltration to web service
}

type Payload struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Variant  string `json:"variant"`
}

type Set struct {
	Advisory       string       `json:"advisory"`
	AdvisoryURL    string       `json:"advisory_url"`
	CuratedBy      string       `json:"curated_by"`
	Tool           string       `json:"tool"`
	Window         model.Window `json:"window"`
	Domain         string       `json:"domain"`
	IP             string       `json:"ip"`
	URL            string       `json:"url"`
	Header         string       `json:"http_header"`
	Sentinel       string       `json:"provisioner_log_sentinel"`
	TerraformBlock string       `json:"terraform_block"`
	Payloads       []Payload    `json:"payloads"`
	VariantModules []string     `json:"harvester_variant_modules"`
	PatchedBuilds  []string     `json:"patched_builds"`
	Techniques     []string     `json:"attack_techniques"`
}

// Build assembles the set at call time.
func Build() Set {
	var payloads []Payload
	for h, p := range scan.Payloads {
		name := scan.MarkerScript
		if strings.HasPrefix(p.Label, "docker") {
			name = scan.MarkerScriptDocker
		}
		payloads = append(payloads, Payload{Filename: name, SHA256: h, Variant: p.Label})
	}
	sort.Slice(payloads, func(i, j int) bool { return payloads[i].Variant < payloads[j].Variant })
	return Set{
		Advisory:    buildinfo.Advisory,
		AdvisoryURL: "https://github.com/coder/coder/security/advisories/" + buildinfo.Advisory,
		CuratedBy:   buildinfo.Attribution,
		Tool:        "leakpatrol " + buildinfo.Version,
		Window:      Window,
		Domain:      "www." + scan.MarkerDomain,
		IP:          scan.MarkerIP,
		URL:         "http://www." + scan.MarkerDomain + scan.MarkerPath,
		// Re-cased from the lower-case marker at runtime so the header's canonical
		// spelling never sits in the binary either (the self-detect test greps
		// case-insensitively, and so would a scanner reading this binary).
		Header:   strings.ToUpper(scan.MarkerHeader[:5]) + "-T" + scan.MarkerHeader[7:],
		Sentinel: scan.MarkerSentinel,
		// Assembled from pieces so the block never appears contiguously in the binary.
		TerraformBlock: "data " + `"external"` + " " + `"telemetry"` + " { ... }",
		Payloads:       payloads,
		VariantModules: VariantModules,
		PatchedBuilds:  version.Patched,
		Techniques:     Techniques,
	}
}

// Write emits the set as indented JSON.
func Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(Build())
}
