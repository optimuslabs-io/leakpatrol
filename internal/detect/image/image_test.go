// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

func tarOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipOf(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	return buf.Bytes()
}

const tf = "data \"external\" \"telemetry\" {\n  program = [\"sh\", \"dlp.sh\"]\n}\n"

func TestDockerSaveLayoutWithPlainAndGzippedLayers(t *testing.T) {
	layer1 := tarOf(t, map[string][]byte{
		"./opt/coder/modules/zed/main.tf": []byte(tf),
		"./etc/hostname":                  []byte("box\n"),
	})
	layer2 := gzipOf(t, tarOf(t, map[string][]byte{
		"home/coder/.bash_history": []byte("curl http://www.coder-infra.com/cli/check\n"),
		"opt/dlp.sh":               []byte("#!/bin/sh\necho benign\n"),
	}))
	image := tarOf(t, map[string][]byte{
		"manifest.json":                   []byte(`[{"Layers":["aaa/layer.tar","blobs/sha256/bbb"]}]`),
		"aaa/layer.tar":                   layer1,
		"blobs/sha256/bbbbbbbbbbbbbbbbbb": layer2,
	})
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(path, image, 0o644); err != nil {
		t.Fatal(err)
	}

	res := New().Run(context.Background(), &engine.Env{Images: []string{path}})
	ids := map[string]model.Finding{}
	for _, f := range res.Findings {
		ids[f.ID] = f
	}
	if f, ok := ids["image.telemetry_block"]; !ok || f.Evidence[0].Path != path+":aaa/opt/coder/modules/zed/main.tf" {
		t.Errorf("telemetry block in plain layer: %+v", f)
	}
	if f, ok := ids["image.history_exfil"]; !ok || f.Severity != model.SevCritical {
		t.Errorf("history in gzipped layer: %+v", f)
	} else if want := path + ":blob:bbbbbbbbbbbb/home/coder/.bash_history"; f.Evidence[0].Path != want {
		t.Errorf("evidence path = %q, want %q", f.Evidence[0].Path, want)
	}
	if f, ok := ids["image.script_name"]; !ok || f.Severity != model.SevLow {
		t.Errorf("weak script name: %+v", f)
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %+v", res.Errors)
	}
}

func TestStdinTar(t *testing.T) {
	image := tarOf(t, map[string][]byte{"x/layer.tar": tarOf(t, map[string][]byte{"main.tf": []byte(tf)})})
	res := New().Run(context.Background(), &engine.Env{Images: []string{"-"}, Stdin: bytes.NewReader(image)})
	if len(res.Findings) != 1 || res.Findings[0].ID != "image.telemetry_block" {
		t.Errorf("stdin scan: %+v", res.Findings)
	}
}

func TestGarbageIsAMaterialError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.tar")
	if err := os.WriteFile(path, []byte("this is not a tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := New().Run(context.Background(), &engine.Env{Images: []string{path}})
	if len(res.Errors) == 0 || !res.Errors[0].Material {
		t.Errorf("unparseable input must degrade the verdict: %+v", res.Errors)
	}
}

func TestMissingTarNeverFallsThroughToContainerCLI(t *testing.T) {
	// A fake docker on PATH that would "succeed": if the tier called it for a
	// mistyped tar path, this test fails.
	bin := t.TempDir()
	fake := filepath.Join(bin, "docker")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho CALLED >&2\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	for _, arg := range []string{"/tmp/rp-no-such.tar", "./typo.tgz", "missing.tar"} {
		res := New().Run(context.Background(), &engine.Env{Images: []string{arg}})
		if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Message, "no such file") {
			t.Errorf("%s: expected a 'no such file' error, got %+v", arg, res.Errors)
		}
		if !strings.Contains(res.Summary, "could not be opened") || strings.Contains(res.Summary, "1 image scanned") {
			t.Errorf("%s: summary must not claim a scan happened: %q", arg, res.Summary)
		}
	}
}

func TestMissingImageWithoutCLI(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no docker/podman/nerdctl
	res := New().Run(context.Background(), &engine.Env{Images: []string{"ghcr.io/example/nope:latest"}})
	if len(res.Errors) != 1 || !res.Errors[0].Material {
		t.Errorf("an unresolvable image must be a material error: %+v", res.Errors)
	}
}
