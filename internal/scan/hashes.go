// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Payload is one of the six harvester scripts the advisory published hashes for.
// The hashes are hex digests, compared against a computed digest and never
// searched for as text, so they can live in the binary as plain literals.
type Payload struct {
	SHA256 string
	// Label says which variant this is, using the module name the advisory labels
	// that hash with, in tool-authored prose that does not contain the script
	// filename. The label describes the build, not the scope of the incident.
	Label string
}

// Payloads is the advisory's hash list. A file whose SHA-256 is in this table is
// the harvester, whatever it is named.
var Payloads = map[string]Payload{
	"7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398": {Label: "docker-variant harvester"},
	"a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247": {Label: "harvester (common variant)"},
	"414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1": {Label: "harvester (aider template variant)"},
	"a64ce3038f2a501c9735abf6a1f9f04cbddbad53371cd68bec0f7510365c8ffa": {Label: "harvester (rstudio-server template variant)"},
	"ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596": {Label: "harvester (windows-rdp template variant)"},
	"7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13": {Label: "harvester (zed template variant)"},
}

func init() {
	for k, p := range Payloads {
		p.SHA256 = k
		Payloads[k] = p
	}
}

// Digest streams r through SHA-256 and returns the lower-case hex digest.
func Digest(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// DigestBytes is Digest over an in-memory buffer.
func DigestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// MatchPayload reports whether a digest is one of the known harvester hashes.
func MatchPayload(digest string) (Payload, bool) {
	p, ok := Payloads[digest]
	return p, ok
}
