// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

func TestQueriesSubstituteSentinelAndKeepPurgeOut(t *testing.T) {
	names, bodies, err := Queries()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 || names[0] != "01_affected_template_versions.sql" || names[2] != "03_provisioner_log_sentinel.sql" {
		t.Fatalf("unexpected query set %v", names)
	}
	for i, b := range bodies {
		if strings.Contains(b, "{{SENTINEL}}") {
			t.Errorf("%s still has the placeholder", names[i])
		}
		if strings.Contains(b, "BEGIN;") || strings.Contains(b, "DELETE") {
			t.Errorf("%s must be read-only", names[i])
		}
	}
	if !strings.Contains(bodies[2], "LIKE '%data.external.telemetry%'") {
		t.Errorf("query 3 must carry the advisory's sentinel after substitution:\n%s", bodies[2])
	}
	p, err := Purge()
	if err != nil || !strings.Contains(p, "DELETE FROM files") || !strings.Contains(p, "COMMIT;") {
		t.Errorf("purge script wrong: %v\n%s", err, p)
	}
}

func TestSplitDSN(t *testing.T) {
	env, ok := splitDSN("postgres://coder:not-a-real-password@db.internal:5433/coder?sslmode=require&foo=bar")
	if !ok {
		t.Fatal("URL DSN should split")
	}
	sort.Strings(env)
	want := []string{"PGDATABASE=coder", "PGHOST=db.internal", "PGPASSWORD=not-a-real-password", "PGPORT=5433", "PGSSLMODE=require", "PGUSER=coder"}
	if strings.Join(env, " ") != strings.Join(want, " ") {
		t.Errorf("got %v want %v", env, want)
	}
	if _, ok := splitDSN("host=x dbname=y"); ok {
		t.Error("conninfo form must fall back to argv")
	}
}

func TestParseCSVAndFindings(t *testing.T) {
	rows, err := parseCSV(strings.NewReader("template,template_version,template_version_id,module_file_id,module_cached_at,version_created_at\naider,v3,tv1,f1,2026-08-31 09:10:11+00,2026-08-31 09:10:00+00\n"))
	if err != nil || len(rows) != 1 || rows[0]["template"] != "aider" {
		t.Fatalf("parseCSV: %v %+v", err, rows)
	}
	f, ok := finding("db", "01_affected_template_versions.sql", rows)
	if !ok || f.Path != model.PathTemplateImport || f.Severity != model.SevMedium || f.Evidence[0].Path != "aider/v3" {
		t.Errorf("query 1 finding: %+v", f)
	}
	if f.Evidence[0].At.IsZero() {
		t.Error("module_cached_at should parse")
	}

	rows3, _ := parseCSV(strings.NewReader("job_type,job_id,workspace_build_id,workspace_id,template_version_id,template_id,template,template_version,workspace,owner_or_initiator,started_at,job_status,workspace_deleted\nworkspace_build,j9,b1,w1,tv1,t1,aider,v3,dev,alice,2026-08-31 10:00:00+00,succeeded,f\n"))
	f3, ok := finding("db", "03_provisioner_log_sentinel.sql", rows3)
	if !ok || f3.Severity != model.SevCritical || f3.Path != model.PathExecuted || f3.Evidence[0].Path != "alice/dev (aider/v3)" {
		t.Errorf("query 3 finding: %+v", f3)
	}
	if _, ok := finding("db", "01_affected_template_versions.sql", nil); ok {
		t.Error("no rows means no finding")
	}
}

// fakePsql installs a psql stand-in on PATH that records how it was invoked and
// answers each query from stdin. No real Postgres, and -- the point of the test
// -- proof that the DSN's password never reaches argv, where `ps` would show it
// to every user on a shared incident-response box.
func fakePsql(t *testing.T, dir string) (argvFile, envFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in is POSIX")
	}
	argvFile = filepath.Join(dir, "argv.txt")
	envFile = filepath.Join(dir, "env.txt")
	script := `#!/bin/sh
printf '%s\n' "$*" >> ` + argvFile + `
env | grep '^PG' | sort >> ` + envFile + `
query=$(cat)
case "$query" in
  *template_version_terraform_values*JOIN\ template_versions*)
    echo "template,template_version,template_version_id,module_file_id,module_cached_at,version_created_at"
    echo "aider,v3,tv1,f1,2026-08-31 09:10:11+00,2026-08-31 09:10:00+00"
    ;;
  *workspace_latest_builds*)
    echo "workspace,owner,transition,job_status,created_at"
    ;;
  *provisioner_job_logs*)
    echo "job_type,job_id,workspace_build_id,workspace_id,template_version_id,template_id,template,template_version,workspace,owner_or_initiator,started_at,job_status,workspace_deleted"
    ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "psql"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argvFile, envFile
}

func TestRunExecutesAllThreeQueriesAndKeepsThePasswordOffArgv(t *testing.T) {
	dir := t.TempDir()
	argvFile, envFile := fakePsql(t, dir)

	const secret = "not-a-real-password"
	dsn := "postgres://coder:" + secret + "@db.internal:5433/coder?sslmode=require"
	res := New().Run(context.Background(), &engine.Env{DSN: dsn})

	argv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("psql was never invoked: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(argv)), "\n")
	if len(lines) != 3 {
		t.Errorf("all three advisory queries must run, got %d psql invocations:\n%s", len(lines), argv)
	}
	for _, l := range lines {
		for _, want := range []string{"--csv", "-f", "-"} {
			if !strings.Contains(l, want) {
				t.Errorf("psql argv missing %q: %s", want, l)
			}
		}
		if strings.Contains(l, secret) || strings.Contains(l, dsn) {
			t.Errorf("the DSN password must never reach argv (ps would show it): %s", l)
		}
	}

	envOut, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PGPASSWORD=" + secret, "PGHOST=db.internal", "PGPORT=5433", "PGDATABASE=coder", "PGSSLMODE=require"} {
		if !strings.Contains(string(envOut), want) {
			t.Errorf("psql env missing %q:\n%s", want, envOut)
		}
	}

	if len(res.Errors) != 0 {
		t.Errorf("unexpected errors: %+v", res.Errors)
	}
	var q1 *model.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "db.cached_module_in_window" {
			q1 = &res.Findings[i]
		}
	}
	if q1 == nil || q1.Severity != model.SevMedium || q1.Path != model.PathTemplateImport || len(q1.Evidence) != 1 {
		t.Fatalf("query 1's row must become a MEDIUM template-import finding, got %+v", res.Findings)
	}
	if q1.Evidence[0].Path != "aider/v3" {
		t.Errorf("evidence = %+v", q1.Evidence[0])
	}
	if !strings.Contains(res.Summary, "1 cached-module") {
		t.Errorf("summary should count the row: %q", res.Summary)
	}
}

func TestRunUsesArgvOnlyForAConninfoDSN(t *testing.T) {
	dir := t.TempDir()
	argvFile, _ := fakePsql(t, dir)

	// A key=value conninfo string has no URL form to split into PG* vars; libpq
	// offers nothing better, so it goes on argv -- and must still work.
	New().Run(context.Background(), &engine.Env{DSN: "host=db.internal dbname=coder"})
	argv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("psql was never invoked: %v", err)
	}
	if !strings.Contains(string(argv), "-d host=db.internal dbname=coder") {
		t.Errorf("conninfo DSN should be passed with -d:\n%s", argv)
	}
}

func TestRunReportsPsqlFailureAsMaterial(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in is POSIX")
	}
	script := "#!/bin/sh\necho 'FATAL: password authentication failed' >&2\nexit 2\n"
	if err := os.WriteFile(filepath.Join(dir, "psql"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	res := New().Run(context.Background(), &engine.Env{DSN: "postgres://u:p@h/d"})
	if len(res.Errors) == 0 {
		t.Fatal("a failing psql must produce errors, not a silent empty result")
	}
	for _, e := range res.Errors {
		if !e.Material {
			t.Errorf("a psql failure is material: %+v", e)
		}
		if strings.Contains(e.Message, "p@h") {
			t.Errorf("error message must not echo the DSN: %s", e.Message)
		}
	}
	if len(res.Findings) != 0 {
		t.Errorf("no findings should be invented from a failed query: %+v", res.Findings)
	}
}
