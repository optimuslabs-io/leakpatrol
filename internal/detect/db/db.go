// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package db runs Coder's own advisory SQL -- the authoritative answer, because
// only the database holds the module-cache timestamps -- through whatever
// Postgres client the operator has, without linking one into this binary.
//
// It runs `psql` when it is on PATH (psql.exe on Windows counts), feeding each
// query on stdin and reading CSV back. When it is not, `--print-only` writes the
// queries out for any client at all: pgAdmin, DBeaver, `kubectl exec ... psql`,
// the RDS Query Editor, Cloud SQL Studio. The purge script is printed and never run.
package db

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	leakpatrol "github.com/optimuslabs-io/leakpatrol"
	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
	"github.com/optimuslabs-io/leakpatrol/internal/scan"
)

// EnvDSN is the variable Coder itself reads its database URL from, so an operator
// on the coderd host usually has it already.
const EnvDSN = "CODER_PG_CONNECTION_URL"

// Queries returns the detection SQL (01-03) with the sentinel substituted, in
// order, keyed by file name.
func Queries() ([]string, []string, error) {
	return load(func(n string) bool { return !strings.HasPrefix(n, "99_") })
}

// Purge returns the remediation script. It is printed by the CLI, never executed.
func Purge() (string, error) {
	names, bodies, err := load(func(n string) bool { return strings.HasPrefix(n, "99_") })
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", fmt.Errorf("purge script missing from embedded sql")
	}
	return bodies[0], nil
}

func load(keep func(string) bool) (names, bodies []string, err error) {
	entries, err := fs.ReadDir(leakpatrol.SQL, "sql")
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if !keep(e.Name()) {
			continue
		}
		b, err := leakpatrol.SQL.ReadFile("sql/" + e.Name())
		if err != nil {
			return nil, nil, err
		}
		names = append(names, e.Name())
		bodies = append(bodies, strings.ReplaceAll(string(b), "{{SENTINEL}}", scan.MarkerSentinel))
	}
	return names, bodies, nil
}

type Detector struct{}

func New() *Detector { return &Detector{} }

func (*Detector) Name() string { return "db" }

func (*Detector) Describe() string {
	return "Coder's advisory SQL via psql: module cache entries in the window, workspaces on those versions, the sentinel in provisioner job logs"
}

func (*Detector) Ready(env *engine.Env) string {
	if DSN(env) == "" {
		return "no --dsn and " + EnvDSN + " is unset"
	}
	if _, err := exec.LookPath("psql"); err != nil {
		return "psql not on PATH -- run `leakpatrol db --print-only` and paste the SQL into any Postgres client"
	}
	return ""
}

// Material: authoritative when it runs, but its absence is a coverage line, not
// a verdict change -- most operator laptops have neither psql nor the DSN. The
// engine names the one thing only this tier can see when deploy ran without it.
func (*Detector) Material() bool { return false }

// DSN resolves the connection string: the flag, then Coder's own variable.
func DSN(env *engine.Env) string {
	if env.DSN != "" {
		return env.DSN
	}
	return os.Getenv(EnvDSN)
}

func (d *Detector) Run(ctx context.Context, env *engine.Env) engine.Result {
	var res engine.Result
	names, bodies, err := Queries()
	if err != nil {
		res.Errors = append(res.Errors, model.ScanError{Detector: d.Name(), Kind: "io", Message: err.Error(), Material: true})
		return res
	}
	dsn := DSN(env)
	counts := make([]int, len(names))
	for i := range names {
		rows, err := run(ctx, dsn, bodies[i])
		if err != nil {
			res.Errors = append(res.Errors, model.ScanError{Detector: d.Name(), Kind: "io", Path: names[i], Message: err.Error(), Material: true})
			continue
		}
		counts[i] = len(rows)
		env.Pulse(d.Name(), fmt.Sprintf("%s: %d rows", names[i], len(rows)))
		if f, ok := finding(d.Name(), names[i], rows); ok {
			res.Findings = append(res.Findings, f)
		}
	}
	res.Summary = fmt.Sprintf("%d cached-module versions, %d workspaces, %d jobs with the sentinel", at(counts, 0), at(counts, 1), at(counts, 2))
	res.Limitations = append(res.Limitations,
		"The db tier is Coder's own advisory SQL and is authoritative for this deployment's database. It cannot see a "+
			"module cache that was already purged, or a second Coder deployment.")
	return res
}

func at(c []int, i int) int {
	if i < len(c) {
		return c[i]
	}
	return 0
}

// run executes one query through psql and returns its rows as column->value maps.
//
// The DSN is not put on the command line: argv is world-readable in `ps`, and a
// Coder database URL carries a password. It is split into PG* environment
// variables for the child instead (libpq's own mechanism). A DSN that is not a URL
// (a key=value conninfo string) falls back to argv, since libpq offers nothing
// better for that form.
func run(ctx context.Context, dsn, query string) ([]map[string]string, error) {
	args := []string{"--csv", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-f", "-"}
	env := os.Environ()
	if pgenv, ok := splitDSN(dsn); ok {
		env = append(env, pgenv...)
	} else {
		args = append([]string{"-d", dsn}, args...)
	}
	cmd := exec.CommandContext(ctx, "psql", args...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(query)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 400 {
			msg = msg[:400] + "…"
		}
		return nil, fmt.Errorf("psql: %v: %s", err, msg)
	}
	return parseCSV(&stdout)
}

// splitDSN turns postgres://user:pass@host:port/db?sslmode=x into libpq env vars.
func splitDSN(dsn string) ([]string, bool) {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, false
	}
	var env []string
	if h := u.Hostname(); h != "" {
		env = append(env, "PGHOST="+h)
	}
	if p := u.Port(); p != "" {
		env = append(env, "PGPORT="+p)
	}
	if u.User != nil {
		env = append(env, "PGUSER="+u.User.Username())
		if pw, ok := u.User.Password(); ok {
			env = append(env, "PGPASSWORD="+pw)
		}
	}
	if db := strings.TrimPrefix(u.Path, "/"); db != "" {
		env = append(env, "PGDATABASE="+db)
	}
	for k, vs := range u.Query() {
		if len(vs) == 0 {
			continue
		}
		switch k {
		case "sslmode", "sslrootcert", "sslcert", "sslkey", "application_name", "connect_timeout", "options", "channel_binding", "gssencmode", "target_session_attrs":
			env = append(env, "PG"+strings.ToUpper(k)+"="+vs[0])
		}
	}
	return env, true
}

func parseCSV(r io.Reader) ([]map[string]string, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	recs, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, nil
	}
	head := recs[0]
	var rows []map[string]string
	for _, rec := range recs[1:] {
		row := map[string]string{}
		for i, v := range rec {
			if i < len(head) {
				row[head[i]] = v
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// finding maps one query's rows to a finding. Evidence carries identifiers and
// timestamps only -- template, version, workspace, owner, job id -- never a log
// line: query 3 selects job metadata, not pjl.output, and this keeps it that way.
func finding(det, name string, rows []map[string]string) (model.Finding, bool) {
	if len(rows) == 0 {
		return model.Finding{}, false
	}
	var f model.Finding
	switch {
	case strings.HasPrefix(name, "01_"):
		f = model.Finding{ID: det + ".cached_module_in_window", Detector: det, Severity: model.SevMedium, Path: model.PathTemplateImport,
			Title:  fmt.Sprintf("Registry modules cached during the window -- %s", engine.Plural(len(rows), "template version")),
			Detail: "A template create, update or dry-run pulled modules from the hijacked registry (advisory query 1). The provisioner's environment leaked."}
		for _, r := range rows {
			f.Evidence = append(f.Evidence, model.Evidence{
				Path: r["template"] + "/" + r["template_version"], Locator: "module_file:" + r["module_file_id"],
				Note: "cached " + r["module_cached_at"], At: parseTime(r["module_cached_at"]),
			})
		}
	case strings.HasPrefix(name, "02_"):
		f = model.Finding{ID: det + ".workspace_on_tainted_version", Detector: det, Severity: model.SevMedium, Path: model.PathWorkspaceBuild,
			Title:  fmt.Sprintf("Workspaces whose latest build uses a poisoned template version -- %s", engine.Plural(len(rows), "workspace")),
			Detail: "Advisory query 2. Each owner's OIDC token, SSH key and external-auth tokens passed through the provisioner with the tampered module."}
		for _, r := range rows {
			f.Evidence = append(f.Evidence, model.Evidence{
				Path: r["owner"] + "/" + r["workspace"], Locator: r["transition"] + " · " + r["job_status"],
				Note: "built " + r["created_at"], At: parseTime(r["created_at"]),
			})
		}
	case strings.HasPrefix(name, "03_"):
		f = model.Finding{ID: det + ".sentinel_in_job_log", Detector: det, Severity: model.SevCritical, Path: model.PathExecuted,
			Title:  fmt.Sprintf("Provisioner jobs whose logs carry the Terraform sentinel -- the harvester ran in %s", engine.Plural(len(rows), "job")),
			Detail: "Advisory query 3. The tampered module's external data source was evaluated, which is the harvester executing with that job's credentials."}
		for _, r := range rows {
			where := r["template"] + "/" + r["template_version"]
			if r["workspace"] != "" {
				where = r["owner_or_initiator"] + "/" + r["workspace"] + " (" + where + ")"
			}
			f.Evidence = append(f.Evidence, model.Evidence{
				Path: where, Locator: r["job_type"] + " job:" + r["job_id"],
				Note: "started " + r["started_at"] + " · " + r["job_status"], At: parseTime(r["started_at"]),
			})
		}
	default:
		return model.Finding{}, false
	}
	return f, true
}

func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999-07", "2006-01-02 15:04:05-07", "2006-01-02 15:04:05.999999+00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
