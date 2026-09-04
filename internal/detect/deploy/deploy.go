// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// Package deploy asks the operator's OWN Coder deployment what happened, over the
// same /api/v2 the coder CLI and the dashboard use. It is the tier that works for
// every operator on every OS with nothing installed: a session token is all it
// needs, and every Coder admin has one from `coder login`.
//
// It is also the only package in leakpatrol permitted to import net/http, and
// `make verify-deps` fails if any other package links it. The client refuses to
// send a request -- or follow a redirect -- to any host but the one named on the
// command line, so the session token can only ever reach the server it came from.
package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/optimuslabs-io/leakpatrol/internal/buildinfo"
	"github.com/optimuslabs-io/leakpatrol/internal/detect/version"
	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/hostfs"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
	"github.com/optimuslabs-io/leakpatrol/internal/scan"
)

const (
	EnvURL   = "CODER_URL"
	EnvToken = "CODER_SESSION_TOKEN"
	// EnvConfigDir is the coder CLI's override for where it keeps `url` and `session`.
	EnvConfigDir = "CODER_CONFIG_DIR"

	pageSize    = 100
	workers     = 8
	maxBody     = 64 << 20
	httpTimeout = 90 * time.Second
)

// Discover resolves the server URL and session token the way the coder CLI
// would: explicit flags, then CODER_URL / CODER_SESSION_TOKEN, then the CLI's own
// login files (<UserConfigDir>/coderv2/url and /session, or CODER_CONFIG_DIR).
// Reading the CLI's session file is what makes `leakpatrol all` work with no
// arguments on a machine that has ever run `coder login`.
//
// An explicit --token-file that cannot be read is an error, not a silent fallback:
// the alternative is a deploy tier that skips for "no token" while the operator
// believes they supplied one.
func Discover(flagServer, tokenFile string) (server, token string, err error) {
	server = strings.TrimSpace(flagServer)
	if server == "" {
		server = strings.TrimSpace(os.Getenv(EnvURL))
	}
	token = strings.TrimSpace(os.Getenv(EnvToken))
	if tokenFile != "" {
		b, rerr := hostfs.ReadFileCapped(tokenFile, 4096)
		if rerr != nil {
			return "", "", fmt.Errorf("--token-file %s: %w", tokenFile, rerr)
		}
		token = strings.TrimSpace(string(b))
		if token == "" {
			return "", "", fmt.Errorf("--token-file %s is empty", tokenFile)
		}
	}
	dir := os.Getenv(EnvConfigDir)
	if dir == "" {
		if base, err := os.UserConfigDir(); err == nil {
			dir = filepath.Join(base, "coderv2")
		}
	}
	if dir != "" {
		if server == "" {
			if b, err := hostfs.ReadFileCapped(filepath.Join(dir, "url"), 4096); err == nil {
				server = strings.TrimSpace(string(b))
			}
		}
		if token == "" {
			if b, err := hostfs.ReadFileCapped(filepath.Join(dir, "session"), 4096); err == nil {
				token = strings.TrimSpace(string(b))
			}
		}
	}
	return server, token, nil
}

type Detector struct{}

func New() *Detector { return &Detector{} }

func (*Detector) Name() string { return "deploy" }

func (*Detector) Describe() string {
	return "your Coder server's API: template versions and workspace builds whose jobs ran in the window, and the sentinel in their provisioner logs"
}

func (*Detector) Ready(env *engine.Env) string {
	switch {
	case env.Offline:
		return "--offline"
	case env.Server == "":
		return "no --server, " + EnvURL + ", or coder CLI login found"
	case env.Token == "":
		return "no " + EnvToken + ", --token-file, or coder CLI session found"
	}
	return ""
}

// Material: without the deployment's own view there is no answer to "did this
// Coder pull the module", so skipping this tier degrades an `all` verdict.
func (*Detector) Material() bool { return true }

// clockSkew pads the advisory window on both sides. Provisioner hosts are not
// NTP-perfect and the window's edges are the usual miss on a 14-hour incident;
// fifteen minutes is cheap. Coder's own SQL (the db tier) is left verbatim.
const clockSkew = 15 * time.Minute

func padded(w model.Window) model.Window {
	return model.Window{Start: w.Start.Add(-clockSkew), End: w.End.Add(clockSkew)}
}

// ---- wire types (Coder's JSON is snake_case) ----

type job struct {
	ID          string     `json:"id"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Status      string     `json:"status"`
}

type template struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type templateVersion struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	TemplateID string    `json:"template_id"`
	CreatedAt  time.Time `json:"created_at"`
	Job        job       `json:"job"`
}

type logEntry struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Output    string    `json:"output"`
}

type workspace struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	OwnerName    string `json:"owner_name"`
	TemplateName string `json:"template_name"`
}

type workspacesPage struct {
	Workspaces []workspace `json:"workspaces"`
	Count      int         `json:"count"`
}

type build struct {
	ID                  string    `json:"id"`
	BuildNumber         int       `json:"build_number"`
	CreatedAt           time.Time `json:"created_at"`
	Transition          string    `json:"transition"`
	TemplateVersionID   string    `json:"template_version_id"`
	TemplateVersionName string    `json:"template_version_name"`
	WorkspaceName       string    `json:"workspace_name"`
	WorkspaceOwnerName  string    `json:"workspace_owner_name"`
	Job                 job       `json:"job"`
}

type organization struct {
	ID string `json:"id"`
}

// ---- client ----

type client struct {
	base  *url.URL
	token string
	hc    *http.Client
}

// restricted is a RoundTripper that refuses any host but the configured one. It
// wraps the default transport (so proxies from the environment still work) and
// checks the REQUEST host, which is the host the token would be sent to.
type restricted struct {
	host string
	rt   http.RoundTripper
}

func (r restricted) RoundTrip(req *http.Request) (*http.Response, error) {
	if !sameHost(req.URL, r.host) {
		return nil, fmt.Errorf("refusing request to %q: only %q is allowed", req.URL.Host, r.host)
	}
	return r.rt.RoundTrip(req)
}

func sameHost(u *url.URL, allowed string) bool {
	return strings.EqualFold(u.Host, allowed)
}

func newClient(server, token string) (*client, error) {
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid server URL %q", server)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected default transport")
	}
	rt := restricted{host: u.Host, rt: base.Clone()}
	hc := &http.Client{
		Transport: rt,
		Timeout:   httpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !sameHost(req.URL, u.Host) {
				return fmt.Errorf("refusing redirect to %q", req.URL.Host)
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	return &client{base: u, token: token, hc: hc}, nil
}

type httpError struct {
	status int
	path   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("GET %s: HTTP %d", e.path, e.status)
}

func (c *client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := *c.base
	u.Path = c.base.Path + path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Coder-Session-Token", c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "leakpatrol/"+buildinfo.Version)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &httpError{status: resp.StatusCode, path: path}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}

// ---- the tier ----

type state struct {
	det  *Detector
	env  *engine.Env
	c    *client
	win  model.Window
	mu   sync.Mutex
	res  engine.Result
	prog struct{ templates, versions, builds, sentinel, inWindow int }

	tainted     map[string]string // template version id -> "template/version"
	tvInWindow  *model.Finding
	tvSentinel  *model.Finding
	wbInWindow  *model.Finding
	wbTainted   *model.Finding
	wbSentinel  *model.Finding
	authFailure bool
	// Coder drops provisioner logs. A missing log on an in-window job is NOT
	// evidence the harvester did not run, so those are counted separately and
	// reported as a material gap; missing logs on out-of-window jobs are routine.
	missingLogsInWindow int
	missingLogsOther    int
}

func (d *Detector) Run(ctx context.Context, env *engine.Env) engine.Result {
	s := &state{det: d, env: env, win: padded(env.Window), tainted: map[string]string{}}
	c, err := newClient(env.Server, env.Token)
	if err != nil {
		s.fail("", err, true)
		return s.res
	}
	s.c = c
	s.tvInWindow = &model.Finding{ID: "deploy.template_version_in_window", Detector: d.Name(), Severity: model.SevMedium, Path: model.PathTemplateImport,
		Title:  "Template versions whose import job ran in the serving window (±15 min clock skew)",
		Detail: "A template create, update or dry-run in the window pulled modules from the hijacked registry. The provisioner's environment leaked. A missing or sentinel-free log does not clear it: Coder drops provisioner logs."}
	s.tvSentinel = &model.Finding{ID: "deploy.sentinel_in_template_job", Detector: d.Name(), Severity: model.SevCritical, Path: model.PathExecuted,
		Title:  "Template import logs carry the Terraform sentinel -- the harvester ran",
		Detail: "The tampered module's external data source was evaluated during the import. Advisory query 3 equivalent, over the API."}
	s.wbInWindow = &model.Finding{ID: "deploy.workspace_build_in_window", Detector: d.Name(), Severity: model.SevMedium, Path: model.PathWorkspaceBuild,
		Title:  "Workspace builds whose job ran in the serving window",
		Detail: "Exposed if module caching was disabled or the version itself was imported in the window (the API cannot tell caching state; the db tier can). Each owner's OIDC token, SSH key and external-auth tokens passed through the provisioner."}
	s.wbTainted = &model.Finding{ID: "deploy.workspace_build_on_tainted_version", Detector: d.Name(), Severity: model.SevMedium, Path: model.PathWorkspaceBuild,
		Title:  "Workspace builds on a template version imported in the window",
		Detail: "The poisoned module was reused from the cache on every later build of that version, until purged. Owner tokens passed through the provisioner."}
	s.wbSentinel = &model.Finding{ID: "deploy.sentinel_in_build_log", Detector: d.Name(), Severity: model.SevCritical, Path: model.PathExecuted,
		Title:  "Workspace build logs carry the Terraform sentinel -- the harvester ran",
		Detail: "The tampered module's external data source was evaluated during a build, with that build's credentials in scope."}

	s.serverVersion(ctx)
	if s.failed() {
		return s.res
	}
	s.templates(ctx)
	if !s.failed() && ctx.Err() == nil {
		s.workspaces(ctx)
	}

	for _, f := range []*model.Finding{s.tvSentinel, s.wbSentinel, s.tvInWindow, s.wbTainted, s.wbInWindow} {
		if len(f.Evidence) > 0 {
			f.Title = fmt.Sprintf("%s -- %d", f.Title, len(f.Evidence))
			s.res.Findings = append(s.res.Findings, *f)
		}
	}
	p := s.prog
	s.res.Summary = fmt.Sprintf("%s · %s (%d in window) · %s since window · %s",
		engine.Plural(p.templates, "template"), engine.Plural(p.versions, "version"), len(s.tainted),
		engine.Plural(p.builds, "build"), engine.Plural(p.sentinel, "sentinel hit"))
	if s.missingLogsInWindow > 0 {
		s.res.Limitations = append(s.res.Limitations, fmt.Sprintf(
			"%s that ran in the window had no retrievable provisioner log. Coder drops logs; their absence is not evidence the harvester did not run. Those jobs stay EXPOSED.",
			engine.Plural(s.missingLogsInWindow, "in-window job")))
	}
	if s.missingLogsOther > 0 {
		s.res.Limitations = append(s.res.Limitations, fmt.Sprintf(
			"%s outside the window had no retrievable log (routine log expiry; not counted against the verdict).",
			engine.Plural(s.missingLogsOther, "job")))
	}
	s.res.Limitations = append(s.res.Limitations,
		"The deploy tier sees only what this session token can: use an owner's token for the whole deployment.",
		"In-window judgements pad the advisory window by 15 minutes on each side for provisioner clock skew.",
		"Template dry-run jobs are not enumerable through the Coder API, so this tier cannot see a dry-run pull at all. A dry-run in the window is caught ONLY by the db tier (advisory query 3, which scans provisioner_job_logs regardless of job type). If you have not run `leakpatrol db`, a clean deploy result does not rule a dry-run out.",
		"A workspace build in the window is exposed only if module caching was disabled or its template version was imported in the window; the API does not expose caching state.")
	return s.res
}

func (s *state) fail(path string, err error, material bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kind := "http"
	var he *httpError
	if errors.As(err, &he) && (he.status == 401 || he.status == 403) {
		s.authFailure = true
		err = fmt.Errorf("%v -- the session token was rejected; run `coder login` or set %s", err, EnvToken)
	}
	if !errors.As(err, &he) {
		kind = "io"
	}
	s.res.Errors = append(s.res.Errors, model.ScanError{Detector: s.det.Name(), Kind: kind, Path: path, Message: err.Error(), Material: material})
}

func (s *state) pulse() {
	s.mu.Lock()
	msg := fmt.Sprintf("%d templates · %d versions (%d in window) · %d builds · %d sentinel hits",
		s.prog.templates, s.prog.versions, len(s.tainted), s.prog.builds, s.prog.sentinel)
	s.mu.Unlock()
	s.env.Pulse(s.det.Name(), msg)
}

// failed reports whether the token was rejected; loops stop early on it rather
// than hammering a server with a bad credential.
func (s *state) failed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authFailure
}

func (s *state) serverVersion(ctx context.Context) {
	var bi struct {
		Version string `json:"version"`
	}
	if err := s.c.get(ctx, "/api/v2/buildinfo", nil, &bi); err != nil {
		s.fail("/api/v2/buildinfo", err, true)
		return
	}
	if f, ok := version.Finding(s.det.Name(), "Coder server", bi.Version); ok {
		s.res.Findings = append(s.res.Findings, f)
	}
}

func (s *state) templates(ctx context.Context) {
	var ts []template
	if err := s.c.get(ctx, "/api/v2/templates", nil, &ts); err != nil {
		// Older servers have only the organization-scoped list.
		var he *httpError
		if !errors.As(err, &he) || he.status != 404 {
			s.fail("/api/v2/templates", err, true)
			return
		}
		var orgs []organization
		if err := s.c.get(ctx, "/api/v2/organizations", nil, &orgs); err != nil {
			s.fail("/api/v2/organizations", err, true)
			return
		}
		for _, o := range orgs {
			var page []template
			if err := s.c.get(ctx, "/api/v2/organizations/"+o.ID+"/templates", nil, &page); err != nil {
				s.fail("/api/v2/organizations/"+o.ID+"/templates", err, true)
				continue
			}
			ts = append(ts, page...)
		}
	}
	s.prog.templates = len(ts)
	s.pulse()

	type vjob struct {
		t template
		v templateVersion
	}
	var (
		wg    sync.WaitGroup
		queue = make(chan vjob)
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				s.versionLogs(ctx, j.t, j.v)
			}
		}()
	}
	for _, t := range ts {
		if ctx.Err() != nil || s.failed() {
			break
		}
		for offset := 0; ; offset += pageSize {
			var vs []templateVersion
			q := url.Values{"include_archived": {"true"}, "limit": {fmt.Sprint(pageSize)}, "offset": {fmt.Sprint(offset)}}
			if err := s.c.get(ctx, "/api/v2/templates/"+t.ID+"/versions", q, &vs); err != nil {
				s.fail("/api/v2/templates/"+t.ID+"/versions", err, true)
				break
			}
			for _, v := range vs {
				s.mu.Lock()
				s.prog.versions++
				name := t.Name + "/" + v.Name
				if inWindow(v.Job, s.win) {
					s.tainted[v.ID] = name
					s.tvInWindow.Evidence = append(s.tvInWindow.Evidence, model.Evidence{
						Path: name, Locator: "job:" + v.Job.ID, Note: "import job " + v.Job.Status, At: jobTime(v.Job),
					})
				}
				s.mu.Unlock()
				// Only jobs that ran at or after the window start can carry the sentinel:
				// the module did not exist before it.
				if !jobTime(v.Job).Before(s.win.Start) {
					queue <- vjob{t, v}
				}
			}
			s.pulse()
			if len(vs) < pageSize {
				break
			}
		}
	}
	close(queue)
	wg.Wait()
}

// missingLog handles a log fetch that came back 404. For an in-window job that is
// a material gap -- the sentinel could not be looked for -- and it is said so
// against the job's name; for any other job it is routine expiry and only
// counted. Returns false when the error was something else and the caller
// should report it normally.
func (s *state) missingLog(name string, j job, err error) bool {
	var he *httpError
	if !errors.As(err, &he) || he.status != 404 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if inWindow(j, s.win) {
		s.missingLogsInWindow++
		s.res.Errors = append(s.res.Errors, model.ScanError{
			Detector: s.det.Name(), Kind: "missing-log", Path: name, Material: true,
			Message: "provisioner log for this in-window job is gone; the sentinel could not be checked and execution cannot be excluded",
		})
	} else {
		s.missingLogsOther++
	}
	return true
}

func (s *state) versionLogs(ctx context.Context, t template, v templateVersion) {
	var logs []logEntry
	path := "/api/v2/templateversions/" + v.ID + "/logs"
	if err := s.c.get(ctx, path, nil, &logs); err != nil {
		if !s.missingLog(t.Name+"/"+v.Name, v.Job, err) {
			s.fail(path, err, true)
		}
		return
	}
	if n, first := sentinelHits(logs); n > 0 {
		s.mu.Lock()
		s.prog.sentinel += n
		s.tvSentinel.Evidence = append(s.tvSentinel.Evidence, model.Evidence{
			Path: t.Name + "/" + v.Name, Locator: "job:" + v.Job.ID + " log:" + fmt.Sprint(first.ID),
			Note: fmt.Sprintf("sentinel on %s", engine.Plural(n, "log line")), At: first.CreatedAt,
		})
		s.mu.Unlock()
		s.pulse()
	}
}

func (s *state) workspaces(ctx context.Context) {
	var all []workspace
	for _, q := range []string{"", "deleted:true"} {
		for offset := 0; ; offset += pageSize {
			var page workspacesPage
			vals := url.Values{"limit": {fmt.Sprint(pageSize)}, "offset": {fmt.Sprint(offset)}}
			if q != "" {
				vals.Set("q", q)
			}
			if err := s.c.get(ctx, "/api/v2/workspaces", vals, &page); err != nil {
				s.fail("/api/v2/workspaces", err, true)
				break
			}
			all = append(all, page.Workspaces...)
			if len(page.Workspaces) < pageSize {
				break
			}
		}
	}

	var (
		wg    sync.WaitGroup
		queue = make(chan workspace)
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range queue {
				s.workspaceBuilds(ctx, w)
			}
		}()
	}
	for _, w := range all {
		if ctx.Err() != nil || s.failed() {
			break
		}
		queue <- w
	}
	close(queue)
	wg.Wait()
}

func (s *state) workspaceBuilds(ctx context.Context, w workspace) {
	path := "/api/v2/workspaces/" + w.ID + "/builds"
	// Page the builds. A single since-bounded call silently truncates at the
	// server's default page cap, so a workspace with many builds in the window
	// could hide the very in-window build (and its sentinel log) we are hunting --
	// a false negative. Offset-paginate like the versions loop and stop on a short
	// page. `since` still bounds every page to the window.
	since := s.win.Start.UTC().Format(time.RFC3339)
	for offset := 0; ; offset += pageSize {
		if ctx.Err() != nil || s.failed() {
			return
		}
		var builds []build
		q := url.Values{"since": {since}, "limit": {fmt.Sprint(pageSize)}, "offset": {fmt.Sprint(offset)}}
		if err := s.c.get(ctx, path, q, &builds); err != nil {
			s.fail(path, err, true)
			return
		}
		s.scanBuilds(ctx, w, builds)
		if len(builds) < pageSize {
			break
		}
	}
	s.pulse()
}

// scanBuilds judges one page of a workspace's builds.
func (s *state) scanBuilds(ctx context.Context, w workspace, builds []build) {
	for _, b := range builds {
		if ctx.Err() != nil {
			return
		}
		who := w.OwnerName + "/" + w.Name
		if b.WorkspaceOwnerName != "" && b.WorkspaceName != "" {
			who = b.WorkspaceOwnerName + "/" + b.WorkspaceName
		}
		loc := fmt.Sprintf("build #%d · %s", b.BuildNumber, b.Transition)
		s.mu.Lock()
		s.prog.builds++
		if inWindow(b.Job, s.win) {
			s.wbInWindow.Evidence = append(s.wbInWindow.Evidence, model.Evidence{
				Path: who, Locator: loc, Note: "on " + w.TemplateName + "/" + b.TemplateVersionName, At: jobTime(b.Job),
			})
		}
		if tv, ok := s.tainted[b.TemplateVersionID]; ok {
			s.wbTainted.Evidence = append(s.wbTainted.Evidence, model.Evidence{
				Path: who, Locator: loc, Note: "on poisoned version " + tv, At: jobTime(b.Job),
			})
		}
		s.mu.Unlock()

		var logs []logEntry
		lpath := "/api/v2/workspacebuilds/" + b.ID + "/logs"
		if err := s.c.get(ctx, lpath, nil, &logs); err != nil {
			if !s.missingLog(who+" "+loc, b.Job, err) {
				s.fail(lpath, err, true)
			}
			continue
		}
		if n, first := sentinelHits(logs); n > 0 {
			s.mu.Lock()
			s.prog.sentinel += n
			s.wbSentinel.Evidence = append(s.wbSentinel.Evidence, model.Evidence{
				Path: who, Locator: loc + " log:" + fmt.Sprint(first.ID),
				Note: fmt.Sprintf("sentinel on %s (%s)", engine.Plural(n, "log line"), w.TemplateName+"/"+b.TemplateVersionName), At: first.CreatedAt,
			})
			s.mu.Unlock()
		}
	}
}

// sentinelHits counts log lines carrying the sentinel. Only the COUNT and the
// first line's id/time leave this function; the output text never does.
func sentinelHits(logs []logEntry) (n int, first logEntry) {
	for _, l := range logs {
		if strings.Contains(strings.ToLower(l.Output), scan.MarkerSentinel) {
			if n == 0 {
				first = l
			}
			n++
		}
	}
	return n, first
}

// inWindow reports whether a job overlapped the serving window: it started or
// completed inside it, or spanned it entirely.
func inWindow(j job, w model.Window) bool {
	in := func(t *time.Time) bool { return t != nil && !t.Before(w.Start) && t.Before(w.End) }
	if in(&j.CreatedAt) || in(j.StartedAt) || in(j.CompletedAt) {
		return true
	}
	if j.StartedAt != nil && j.CompletedAt != nil && j.StartedAt.Before(w.Start) && !j.CompletedAt.Before(w.End) {
		return true
	}
	return false
}

// jobTime is the best single timestamp for a job: when it started, else when it
// was created.
func jobTime(j job) time.Time {
	if j.StartedAt != nil {
		return *j.StartedAt
	}
	return j.CreatedAt
}
