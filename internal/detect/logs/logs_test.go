// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package logs

import (
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

const fw = "2026-08-31T09:12:44Z ALLOW 10.0.3.17 -> 199.91.220.205:80\n" +
	"2026-08-31T09:12:45Z ALLOW 10.0.3.17 -> 140.82.112.3:443\n" +
	"2026-08-31T09:13:02Z GET http://www.coder-infra.com/cli/check\n"

func TestLogsTierPlainGzipAndStdin(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "fw.log")
	if err := os.WriteFile(plain, []byte(fw), 0o644); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(fw))
	_ = zw.Close()
	gzPath := filepath.Join(dir, "fw.log.gz")
	if err := os.WriteFile(gzPath, gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	env := &engine.Env{Home: dir, Logs: []string{plain, gzPath, "-"}, Stdin: strings.NewReader("provisioner: module.zed.data.external.telemetry: Reading...\n")}
	res := New().Run(context.Background(), env)

	var egress, sentinel *model.Finding
	for i := range res.Findings {
		switch res.Findings[i].ID {
		case "logs.egress_hit":
			egress = &res.Findings[i]
		case "logs.sentinel_hit":
			sentinel = &res.Findings[i]
		}
	}
	if egress == nil || egress.Path != model.PathEgress || egress.Severity != model.SevCritical {
		t.Fatalf("egress finding wrong: %+v", egress)
	}
	// 2 hits per file (IP line; domain+path on one line count as 2 markers) x 2 files.
	if len(egress.Evidence) != 6 {
		t.Errorf("expected 6 egress evidence rows, got %d", len(egress.Evidence))
	}
	for _, e := range egress.Evidence {
		if e.SourceLine == 0 || e.Source == "" || e.Path != "" {
			t.Errorf("egress evidence must cite source:line only: %+v", e)
		}
	}
	if sentinel == nil || sentinel.Path != model.PathExecuted || sentinel.Evidence[0].Source != "stdin" {
		t.Fatalf("sentinel finding wrong: %+v", sentinel)
	}
	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %+v", res.Errors)
	}
}

func TestLogsTierMissingFileIsMaterial(t *testing.T) {
	res := New().Run(context.Background(), &engine.Env{Logs: []string{"/definitely/not/here.log"}})
	if len(res.Errors) != 1 || !res.Errors[0].Material {
		t.Errorf("a missing log export must be a material error: %+v", res.Errors)
	}
}
