// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
)

var win = model.Window{
	Start: time.Date(2026, 8, 31, 7, 35, 0, 0, time.UTC),
	End:   time.Date(2026, 8, 31, 21, 45, 0, 0, time.UTC),
}

func ts(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

// calls records the query shapes the tier actually used. Dropping any of these
// (archived versions, the deleted-workspace sweep) is a silent CLEAN on a real
// org, so they are asserted as having HAPPENED, not merely tolerated.
type calls struct {
	mu              sync.Mutex
	deletedSweep    bool
	versionOffsets  []string
	workspaceOffset []string
}

func (c *calls) note(field *[]string, v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*field = append(*field, v)
}

// fakeCoder is enough of /api/v2 to exercise every branch: one template with a
// version imported before the window, one inside it (whose logs carry the
// sentinel), a workspace with a build inside the window and one later build on the
// poisoned version whose logs also carry the sentinel.
func fakeCoder(t *testing.T) (*httptest.Server, *calls) {
	t.Helper()
	c := &calls{}
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Coder-Session-Token") != "tok" {
				w.WriteHeader(401)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("/api/v2/buildinfo", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]string{"version": "v2.36.3+abc"})
	})
	mux.HandleFunc("/api/v2/templates", auth(func(w http.ResponseWriter, r *http.Request) {
		j(w, []map[string]string{{"id": "t1", "name": "aider"}})
	}))
	mux.HandleFunc("/api/v2/templates/t1/versions", auth(func(w http.ResponseWriter, r *http.Request) {
		// Archived versions still pulled the module during the window, so dropping
		// include_archived would silently clear a real deployment.
		if r.URL.Query().Get("include_archived") != "true" {
			t.Errorf("template versions must be listed with include_archived=true, got %q", r.URL.RawQuery)
		}
		if r.URL.Query().Get("limit") != "100" {
			t.Errorf("template versions must page with limit=100, got %q", r.URL.RawQuery)
		}
		c.note(&c.versionOffsets, r.URL.Query().Get("offset"))
		if r.URL.Query().Get("offset") != "0" {
			j(w, []any{})
			return
		}
		j(w, []map[string]any{
			{"id": "v-old", "name": "old", "created_at": "2026-08-01T00:00:00Z",
				"job": map[string]any{"id": "j-old", "created_at": "2026-08-01T00:00:00Z", "started_at": "2026-08-01T00:00:01Z", "completed_at": "2026-08-01T00:01:00Z", "status": "succeeded"}},
			{"id": "v-bad", "name": "bad", "created_at": "2026-08-31T10:00:00Z",
				"job": map[string]any{"id": "j-bad", "created_at": "2026-08-31T10:00:00Z", "started_at": "2026-08-31T10:00:01Z", "completed_at": "2026-08-31T10:01:00Z", "status": "succeeded"}},
			// In-window (inside the 15-minute skew pad, even) with its log gone: must
			// stay EXPOSED and be flagged as a gap, never read as "no sentinel".
			{"id": "v-gone", "name": "gone", "created_at": "2026-08-31T07:25:00Z",
				"job": map[string]any{"id": "j-gone", "created_at": "2026-08-31T07:25:00Z", "started_at": "2026-08-31T07:25:01Z", "completed_at": "2026-08-31T07:26:00Z", "status": "succeeded"}},
			// Out-of-window with its log gone: routine expiry, counted only.
			{"id": "v-later", "name": "later", "created_at": "2026-09-02T08:00:00Z",
				"job": map[string]any{"id": "j-later", "created_at": "2026-09-02T08:00:00Z", "started_at": "2026-09-02T08:00:01Z", "completed_at": "2026-09-02T08:01:00Z", "status": "succeeded"}},
		})
	}))
	mux.HandleFunc("/api/v2/templateversions/v-gone/logs", auth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	mux.HandleFunc("/api/v2/templateversions/v-later/logs", auth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	mux.HandleFunc("/api/v2/templateversions/v-bad/logs", auth(func(w http.ResponseWriter, r *http.Request) {
		j(w, []map[string]any{
			{"id": 1, "created_at": "2026-08-31T10:00:05Z", "output": "Initializing modules..."},
			{"id": 2, "created_at": "2026-08-31T10:00:07Z", "output": "module.aider.data.external.telemetry: Reading..."},
		})
	}))
	mux.HandleFunc("/api/v2/templateversions/v-old/logs", auth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("logs for a pre-window version must not be fetched")
		j(w, []any{})
	}))
	mux.HandleFunc("/api/v2/workspaces", auth(func(w http.ResponseWriter, r *http.Request) {
		c.note(&c.workspaceOffset, r.URL.Query().Get("offset"))
		if r.URL.Query().Get("q") == "deleted:true" {
			c.mu.Lock()
			c.deletedSweep = true
			c.mu.Unlock()
			j(w, map[string]any{"workspaces": []any{}, "count": 0})
			return
		}
		if r.URL.Query().Get("offset") != "0" {
			j(w, map[string]any{"workspaces": []any{}, "count": 0})
			return
		}
		j(w, map[string]any{"workspaces": []map[string]any{{"id": "w1", "name": "dev", "owner_name": "alice", "template_name": "aider"}}, "count": 1})
	}))
	mux.HandleFunc("/api/v2/workspaces/w1/builds", auth(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Query().Get("since"), "2026-08-31T07:20:00") {
			t.Errorf("builds must be filtered from the skew-padded window start, got since=%q", r.URL.Query().Get("since"))
		}
		j(w, []map[string]any{
			{"id": "b1", "build_number": 7, "created_at": "2026-08-31T12:00:00Z", "transition": "start", "template_version_id": "v-old", "template_version_name": "old",
				"job": map[string]any{"id": "jb1", "created_at": "2026-08-31T12:00:00Z", "started_at": "2026-08-31T12:00:01Z", "completed_at": "2026-08-31T12:02:00Z", "status": "succeeded"}},
			{"id": "b2", "build_number": 8, "created_at": "2026-09-02T12:00:00Z", "transition": "start", "template_version_id": "v-bad", "template_version_name": "bad",
				"job": map[string]any{"id": "jb2", "created_at": "2026-09-02T12:00:00Z", "started_at": "2026-09-02T12:00:01Z", "completed_at": "2026-09-02T12:02:00Z", "status": "succeeded"}},
		})
	}))
	mux.HandleFunc("/api/v2/workspacebuilds/b1/logs", auth(func(w http.ResponseWriter, r *http.Request) { j(w, []any{}) }))
	mux.HandleFunc("/api/v2/workspacebuilds/b2/logs", auth(func(w http.ResponseWriter, r *http.Request) {
		j(w, []map[string]any{{"id": 9, "created_at": "2026-09-02T12:00:30Z", "output": "data.external.telemetry: Read complete"}})
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, c
}

func TestDeployTierEndToEnd(t *testing.T) {
	srv, c := fakeCoder(t)
	env := &engine.Env{Server: srv.URL, Token: "tok", Window: win}
	res := New().Run(context.Background(), env)
	c.mu.Lock()
	deletedSweep := c.deletedSweep
	c.mu.Unlock()
	if !deletedSweep {
		t.Error("the tier must sweep deleted workspaces (q=deleted:true): a deleted workspace still built from a poisoned version")
	}
	// Exactly one error: the in-window job whose log is gone. The out-of-window
	// 404 is routine and must not appear.
	if len(res.Errors) != 1 || res.Errors[0].Kind != "missing-log" || !res.Errors[0].Material || res.Errors[0].Path != "aider/gone" {
		t.Fatalf("expected one material missing-log error for aider/gone, got %+v", res.Errors)
	}
	joined := strings.Join(res.Limitations, "\n")
	if !strings.Contains(joined, "1 in-window job") || !strings.Contains(joined, "1 job outside the window") {
		t.Errorf("limitations should count both missing-log classes:\n%s", joined)
	}
	ids := map[string]model.Finding{}
	for _, f := range res.Findings {
		ids[f.ID] = f
	}
	if f, ok := ids["deploy.unpatched"]; !ok || !strings.Contains(f.Title, "2.36.3") {
		t.Errorf("server version: %+v", f)
	}
	if f, ok := ids["deploy.template_version_in_window"]; !ok || len(f.Evidence) != 2 || f.Path != model.PathTemplateImport {
		t.Errorf("template versions in window (bad + gone, via skew pad): %+v", f)
	}
	if f, ok := ids["deploy.sentinel_in_template_job"]; !ok || f.Severity != model.SevCritical || f.Path != model.PathExecuted || f.Evidence[0].Locator != "job:j-bad log:2" {
		t.Errorf("sentinel in template job: %+v", f)
	}
	if f, ok := ids["deploy.workspace_build_in_window"]; !ok || f.Evidence[0].Path != "alice/dev" || f.Evidence[0].Locator != "build #7 · start" {
		t.Errorf("build in window: %+v", f)
	}
	if f, ok := ids["deploy.workspace_build_on_tainted_version"]; !ok || f.Evidence[0].Locator != "build #8 · start" {
		t.Errorf("build on tainted version: %+v", f)
	}
	if f, ok := ids["deploy.sentinel_in_build_log"]; !ok || f.Severity != model.SevCritical {
		t.Errorf("sentinel in build log: %+v", f)
	}
	for _, f := range res.Findings {
		for _, e := range f.Evidence {
			if strings.Contains(e.Note, "Reading") || strings.Contains(e.Locator, "Reading") {
				t.Errorf("log output text leaked into evidence: %+v", e)
			}
		}
	}
}

func TestRejectedTokenStopsEarly(t *testing.T) {
	srv, _ := fakeCoder(t)
	res := New().Run(context.Background(), &engine.Env{Server: srv.URL, Token: "wrong", Window: win})
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Message, "rejected") {
		t.Fatalf("expected a token-rejected error, got %+v", res.Errors)
	}
	if len(res.Errors) > 2 {
		t.Errorf("a rejected token must stop the tier, not hammer every endpoint: %d errors", len(res.Errors))
	}
}

func TestClientRefusesOtherHostsAndRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("request reached a host that is not the configured server: %s", r.Host)
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/v2/buildinfo", http.StatusFound)
	}))
	defer redirector.Close()

	c, err := newClient(redirector.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := c.get(context.Background(), "/api/v2/buildinfo", nil, &out); err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Errorf("cross-host redirect must be refused, got %v", err)
	}

	c2, _ := newClient(other.URL, "tok")
	c2.base.Host = "evil.example:1" // simulate a request whose host drifted from the allowed one
	if err := c2.get(context.Background(), "/x", nil, &out); err == nil || !strings.Contains(err.Error(), "refusing request") {
		t.Errorf("request to a non-configured host must be refused, got %v", err)
	}
}

// A deployment with more than one page of template versions is the normal case
// for any real org. If the offset loop stops after page 1, the poisoned version
// on page 2 is never seen and the tool reports a confident, wrong CLEAN. This
// puts the ONLY in-window version -- and the only sentinel -- on the second page.
func TestPaginationReachesTheSentinelOnPageTwo(t *testing.T) {
	var (
		mu      sync.Mutex
		offsets []string
	)
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
	mux.HandleFunc("/api/v2/buildinfo", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]string{"version": "v2.37.0"})
	})
	mux.HandleFunc("/api/v2/templates", func(w http.ResponseWriter, r *http.Request) {
		j(w, []map[string]string{{"id": "t1", "name": "aider"}})
	})
	mux.HandleFunc("/api/v2/templates/t1/versions", func(w http.ResponseWriter, r *http.Request) {
		off := r.URL.Query().Get("offset")
		mu.Lock()
		offsets = append(offsets, off)
		mu.Unlock()
		switch off {
		case "0":
			// A full page of out-of-window versions: the loop must not stop here.
			var page []map[string]any
			for i := 0; i < 100; i++ {
				id := fmt.Sprintf("v-pad-%d", i)
				page = append(page, map[string]any{
					"id": id, "name": id, "created_at": "2026-07-01T00:00:00Z",
					"job": map[string]any{"id": "j-" + id, "created_at": "2026-07-01T00:00:00Z",
						"started_at": "2026-07-01T00:00:01Z", "completed_at": "2026-07-01T00:01:00Z", "status": "succeeded"},
				})
			}
			j(w, page)
		case "100":
			j(w, []map[string]any{{
				"id": "v-bad", "name": "bad", "created_at": "2026-08-31T10:00:00Z",
				"job": map[string]any{"id": "j-bad", "created_at": "2026-08-31T10:00:00Z",
					"started_at": "2026-08-31T10:00:01Z", "completed_at": "2026-08-31T10:01:00Z", "status": "succeeded"},
			}})
		default:
			j(w, []any{})
		}
	})
	mux.HandleFunc("/api/v2/templateversions/v-bad/logs", func(w http.ResponseWriter, r *http.Request) {
		j(w, []map[string]any{{"id": 7, "created_at": "2026-08-31T10:00:07Z", "output": "module.aider.data.external.telemetry: Reading..."}})
	})
	mux.HandleFunc("/api/v2/workspaces", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]any{"workspaces": []any{}, "count": 0})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })

	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := New().Run(context.Background(), &engine.Env{Server: srv.URL, Token: "tok", Window: win})

	mu.Lock()
	got := strings.Join(offsets, ",")
	mu.Unlock()
	if !strings.Contains(got, "100") {
		t.Fatalf("the version loop must request offset=100; offsets requested: %s", got)
	}
	var sentinel, inWindow bool
	for _, f := range res.Findings {
		switch f.ID {
		case "deploy.sentinel_in_template_job":
			sentinel = true
		case "deploy.template_version_in_window":
			inWindow = true
		}
	}
	if !sentinel || !inWindow {
		t.Errorf("the page-2 poisoned version must be found: sentinel=%v inWindow=%v findings=%+v", sentinel, inWindow, res.Findings)
	}
}

// A workspace with more builds than one page must not hide the in-window build on
// a later page. Before builds were offset-paginated, a single since-only call
// truncated at the server's page cap and this build (and its sentinel) vanished.
func TestWorkspaceBuildPaginationReachesSentinel(t *testing.T) {
	var (
		mu           sync.Mutex
		buildOffsets []string
	)
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
	buildJSON := func(id string, num int, at string) map[string]any {
		return map[string]any{
			"id": id, "build_number": num, "created_at": at, "transition": "start",
			"template_version_id": "v-x", "template_version_name": "x",
			"job": map[string]any{"id": "j-" + id, "created_at": at, "started_at": at, "completed_at": at, "status": "succeeded"},
		}
	}
	mux.HandleFunc("/api/v2/buildinfo", func(w http.ResponseWriter, r *http.Request) {
		j(w, map[string]string{"version": "v2.37.0"})
	})
	mux.HandleFunc("/api/v2/templates", func(w http.ResponseWriter, r *http.Request) { j(w, []any{}) })
	mux.HandleFunc("/api/v2/workspaces", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "deleted:true" || r.URL.Query().Get("offset") != "0" {
			j(w, map[string]any{"workspaces": []any{}, "count": 0})
			return
		}
		j(w, map[string]any{"workspaces": []map[string]any{{"id": "w1", "name": "dev", "owner_name": "alice", "template_name": "aider"}}, "count": 1})
	})
	mux.HandleFunc("/api/v2/workspaces/w1/builds", func(w http.ResponseWriter, r *http.Request) {
		off := r.URL.Query().Get("offset")
		mu.Lock()
		buildOffsets = append(buildOffsets, off)
		mu.Unlock()
		switch off {
		case "0":
			var page []map[string]any
			for i := 0; i < 100; i++ { // a full page of out-of-window builds
				page = append(page, buildJSON(fmt.Sprintf("bp-%d", i), i, "2026-07-01T00:00:00Z"))
			}
			j(w, page)
		case "100":
			j(w, []map[string]any{buildJSON("b-bad", 999, "2026-08-31T10:00:00Z")}) // in-window, page 2
		default:
			j(w, []any{})
		}
	})
	// The in-window build's log carries the sentinel; every other build's log is empty.
	mux.HandleFunc("/api/v2/workspacebuilds/", func(w http.ResponseWriter, r *http.Request) { j(w, []any{}) })
	mux.HandleFunc("/api/v2/workspacebuilds/b-bad/logs", func(w http.ResponseWriter, r *http.Request) {
		j(w, []map[string]any{{"id": 5, "created_at": "2026-08-31T10:00:05Z", "output": "module.aider.data.external.telemetry: Reading..."}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })

	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := New().Run(context.Background(), &engine.Env{Server: srv.URL, Token: "tok", Window: win})

	mu.Lock()
	got := strings.Join(buildOffsets, ",")
	mu.Unlock()
	if !strings.Contains(got, "100") {
		t.Fatalf("the build loop must request offset=100; offsets requested: %s", got)
	}
	var sentinel bool
	for _, f := range res.Findings {
		if f.ID == "deploy.sentinel_in_build_log" {
			sentinel = true
		}
	}
	if !sentinel {
		t.Errorf("the page-2 in-window build's sentinel must be found; findings=%+v", res.Findings)
	}
}

func TestReadyReasons(t *testing.T) {
	d := New()
	if r := d.Ready(&engine.Env{Offline: true, Server: "x", Token: "y"}); r != "--offline" {
		t.Errorf("offline: %q", r)
	}
	if r := d.Ready(&engine.Env{Token: "y"}); !strings.Contains(r, "--server") {
		t.Errorf("no server: %q", r)
	}
	if r := d.Ready(&engine.Env{Server: "x"}); !strings.Contains(r, "CODER_SESSION_TOKEN") {
		t.Errorf("no token: %q", r)
	}
}

func TestDiscoverReadsCoderCLILogin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvConfigDir, dir)
	t.Setenv(EnvURL, "")
	t.Setenv(EnvToken, "")
	writeFile(t, dir+"/url", "https://coder.example.com\n")
	writeFile(t, dir+"/session", "abc-token\n")
	s, tok, err := Discover("", "")
	if err != nil || s != "https://coder.example.com" || tok != "abc-token" {
		t.Errorf("Discover = %q %q %v", s, tok, err)
	}
	s, _, _ = Discover("https://flag.example", "")
	if s != "https://flag.example" {
		t.Errorf("flag must win: %q", s)
	}
	if _, _, err := Discover("", dir+"/does-not-exist"); err == nil {
		t.Error("an unreadable --token-file must be an error, not a silent skip")
	}
	writeFile(t, dir+"/empty", "\n")
	if _, _, err := Discover("", dir+"/empty"); err == nil {
		t.Error("an empty --token-file must be an error")
	}
}

func TestInWindow(t *testing.T) {
	cases := []struct {
		name string
		j    job
		want bool
	}{
		{"inside", job{CreatedAt: *ts("2026-08-31T10:00:00Z")}, true},
		{"before", job{CreatedAt: *ts("2026-08-31T07:00:00Z"), StartedAt: ts("2026-08-31T07:10:00Z"), CompletedAt: ts("2026-08-31T07:20:00Z")}, false},
		{"after", job{CreatedAt: *ts("2026-09-01T00:00:00Z")}, false},
		{"spans", job{CreatedAt: *ts("2026-08-31T07:00:00Z"), StartedAt: ts("2026-08-31T07:00:00Z"), CompletedAt: ts("2026-08-31T22:00:00Z")}, true},
		{"ends inside", job{CreatedAt: *ts("2026-08-31T07:00:00Z"), StartedAt: ts("2026-08-31T07:00:00Z"), CompletedAt: ts("2026-08-31T08:00:00Z")}, true},
		{"at end (exclusive)", job{CreatedAt: *ts("2026-08-31T21:45:00Z")}, false},
	}
	for _, c := range cases {
		if got := inWindow(c.j, win); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// The padded window the tier actually judges by.
	p := padded(win)
	if !inWindow(job{CreatedAt: *ts("2026-08-31T07:22:00Z")}, p) || !inWindow(job{CreatedAt: *ts("2026-08-31T21:58:00Z")}, p) {
		t.Error("15-minute skew pad must admit jobs just outside the advisory window")
	}
	if inWindow(job{CreatedAt: *ts("2026-08-31T07:19:00Z")}, p) {
		t.Error("skew pad must not admit jobs 16 minutes early")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := writeAll(path, content); err != nil {
		t.Fatal(err)
	}
}
