// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func TestIsPatched(t *testing.T) {
	cases := map[string]bool{
		"2.37.0": true, "2.37.1": true, "2.38.0": true, "3.0.0": true,
		"2.36.4": true, "2.36.3": false, "2.36.0": false,
		"2.35.7": true, "2.35.6": false,
		"2.34.9": true, "2.34.8": false,
		"2.33.99": false, "1.99.0": false,
	}
	for v, want := range cases {
		maj, min, pat, ok := Parse("Coder v" + v + "+abc123")
		if !ok {
			t.Fatalf("parse %q", v)
		}
		if got := IsPatched(maj, min, pat); got != want {
			t.Errorf("%s: got %v want %v", v, got, want)
		}
	}
	if _, _, _, ok := Parse("no version here"); ok {
		t.Error("garbage parsed")
	}
}

func TestFindingWording(t *testing.T) {
	f, ok := Finding("deploy", "Coder server", "v2.36.3")
	if !ok || f.ID != "deploy.unpatched" {
		t.Errorf("%+v", f)
	}
	f, _ = Finding("coder-version", "coder CLI", "2.37.0")
	if f.ID != "coder-version.patched" {
		t.Errorf("%+v", f)
	}
	if New().Name() == "version" {
		t.Error("the tier must not be called `version`: that word is the tool's own version")
	}
}
