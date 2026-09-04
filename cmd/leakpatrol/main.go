// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

// leakpatrol tells a Coder operator whether their deployment was exposed to
// the 2026-08-31 registry hijack (GHSA-vx42-ghc9-gw65), through which path, and
// therefore what to rotate.
//
// It is read-only. Its only network traffic is to the Coder server you name, and
// only in the deploy tier. It never contacts the exfil endpoint, never executes
// anything it finds, and never prints the contents of a file.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/optimuslabs-io/leakpatrol/internal/buildinfo"
	"github.com/optimuslabs-io/leakpatrol/internal/detect/db"
	"github.com/optimuslabs-io/leakpatrol/internal/detect/deploy"
	"github.com/optimuslabs-io/leakpatrol/internal/detect/fs"
	"github.com/optimuslabs-io/leakpatrol/internal/detect/image"
	"github.com/optimuslabs-io/leakpatrol/internal/detect/logs"
	"github.com/optimuslabs-io/leakpatrol/internal/detect/version"
	"github.com/optimuslabs-io/leakpatrol/internal/engine"
	"github.com/optimuslabs-io/leakpatrol/internal/hostfs"
	"github.com/optimuslabs-io/leakpatrol/internal/iocs"
	"github.com/optimuslabs-io/leakpatrol/internal/model"
	"github.com/optimuslabs-io/leakpatrol/internal/report"
)

type repeatable []string

func (r *repeatable) String() string     { return strings.Join(*r, ",") }
func (r *repeatable) Set(v string) error { *r = append(*r, v); return nil }

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin)) }

// run is the whole CLI, with its streams injected so tests can drive every
// operator-facing contract in-process -- the false-CLEAN refusals above all, which
// live here in the wiring rather than in any detector's unit tests.
func run(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	// fail prints a tool error and returns the tool-error exit code. Every path
	// that did NOT produce a report goes through here, so "exit 0" keeps meaning
	// "a scan ran and a verdict was printed" -- never "nothing happened".
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "leakpatrol: "+format+"\n", a...)
		return model.ExitToolError
	}

	if len(args) == 0 {
		usage(stderr)
		return model.ExitToolError
	}
	sub := args[0]
	switch sub {
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	case "-v", "--version":
		printVersion(stdout)
		return 0
	}

	fl := flag.NewFlagSet("leakpatrol "+sub, flag.ContinueOnError)
	fl.SetOutput(stderr)
	var (
		roots, logFiles, images repeatable

		server    = fl.String("server", "", "Coder server URL for the deploy tier (default $CODER_URL, then the coder CLI's login)")
		tokenFile = fl.String("token-file", "", "file holding a Coder session token (default $CODER_SESSION_TOKEN, then the coder CLI's session)")
		offline   = fl.Bool("offline", os.Getenv("LEAKPATROL_OFFLINE") != "", "never open a network connection; skips the deploy tier")

		dsn       = fl.String("dsn", "", "Postgres URL for the db tier (default $"+db.EnvDSN+")")
		printOnly = fl.Bool("print-only", false, "db: print Coder's advisory SQL instead of running it")
		purge     = fl.Bool("purge", false, "db: print Coder's purge transaction (never executed by this tool)")

		home        = fl.String("home", "", "override the home directory used for default fs roots and ~ display")
		maxFileSize = fl.Int64("max-file-size", fs.DefaultMaxFileSize, "read and hash at most this many bytes of any one text file")
		timeout     = fl.Duration("timeout", 60*time.Minute, "global deadline")
		tierTimeout = fl.Duration("tier-timeout", 30*time.Minute, "per-tier deadline")

		asJSON    = fl.Bool("json", false, "emit the machine-readable report on stdout")
		colorMode = fl.String("color", "auto", "auto | always | never")
		quiet     = fl.Bool("quiet", false, "print only the verdict block (verdict, facts, footer) and no progress")
		verbose   = fl.Bool("verbose", false, "print every evidence row instead of a sample")
		noAnim    = fl.Bool("no-animation", false, "skip the animated logo (progress still prints)")
	)
	fl.Var(&roots, "roots", "fs: directory to scan (repeatable; default per-OS locations on THIS machine)")
	fl.Var(&logFiles, "logs", "logs: file, .gz, or - for stdin (repeatable)")
	fl.Var(&images, "image", "image: a `docker save` tar, - for stdin, or an image reference (repeatable)")
	fl.Usage = func() { usage(stderr) }
	if err := fl.Parse(args[1:]); err != nil {
		return model.ExitToolError
	}
	pos := fl.Args()

	// Go's flag package stops at the first non-flag, so `image x.tar --json` would
	// otherwise scan "--json" as an image and never parse it. Refuse anything that
	// looks like a flag in the positional list; only "-" (stdin) is legitimate.
	for _, p := range pos {
		if strings.HasPrefix(p, "-") && p != "-" {
			return fail("%s: unexpected argument %q -- flags go BEFORE files: leakpatrol %s [flags] <files…>", sub, p, sub)
		}
	}

	h, err := hostfs.Home(*home)
	if err != nil {
		return fail("cannot resolve home directory: %v", err)
	}
	srv, tok, err := deploy.Discover(*server, *tokenFile)
	if err != nil {
		return fail("%v", err)
	}
	env := &engine.Env{
		Home: h, Roots: roots, Logs: logFiles, Images: images,
		Server: srv, Token: tok, Offline: *offline, DSN: *dsn,
		MaxFileSize: *maxFileSize, Window: iocs.Window, Stdin: stdin,
	}

	var dets []engine.Detector
	all := false
	switch sub {
	case "all":
		all = true
		dets = allDetectors()
	case "deploy":
		dets = []engine.Detector{deploy.New()}
	case "db":
		if *printOnly || *purge {
			return printSQL(stdout, fail, *purge)
		}
		dets = []engine.Detector{db.New()}
	case "fs":
		env.Roots = append(env.Roots, pos...)
		dets = []engine.Detector{fs.New()}
	case "image":
		env.Images = append(env.Images, pos...)
		dets = []engine.Detector{image.New()}
	case "logs":
		env.Logs = append(env.Logs, pos...)
		dets = []engine.Detector{logs.New()}
	case "coder-version":
		dets = []engine.Detector{version.New()}
	case "version":
		// `version` is the tool's own version plus the coder CLI check, kubectl-style:
		// typing it must never produce a CLEAN that reads like a scan result.
		printVersion(stdout)
		return coderVersionLine(stdout)
	case "iocs":
		if err := iocs.Write(stdout); err != nil {
			return model.ExitToolError
		}
		return 0
	case "preflight":
		return preflight(stdout, env, *asJSON, *colorMode)
	default:
		fmt.Fprintf(stderr, "leakpatrol: unknown command %q\n\n", sub)
		usage(stderr)
		return model.ExitToolError
	}

	// An explicit single-tier command that cannot run is a tool error, exactly like
	// `image` with no tar. It must not fall through to a report, because a report
	// with a verdict on it is read as "the tool looked". `all` is the only mode that
	// tolerates skips, and it records each one in COVERAGE.
	if !all {
		for _, d := range dets {
			if reason := d.Ready(env); reason != "" {
				return fail("%s: cannot run -- %s", sub, reason)
			}
		}
	}
	// Input files are checked before anything runs, in every mode: a mistyped tar
	// or log path is a typo to fix now, not a "could not be opened" row under an
	// INDETERMINATE verdict that still tells the operator what to purge.
	for _, p := range env.Logs {
		if p != "-" {
			if _, err := os.Stat(p); err != nil {
				return fail("logs: %s: %v", p, err)
			}
		}
	}
	for _, p := range env.Images {
		if p != "-" && image.LooksLikePath(p) {
			if _, err := os.Stat(p); err != nil {
				return fail("image: %s: no such file (a bare image reference is handed to docker/podman/nerdctl; a path must exist)", p)
			}
		}
	}

	// Ctrl-C produces a partial report rather than nothing.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	var prog engine.Progress
	if !*quiet {
		style := report.Style{Color: useColor(*colorMode, stderr)}
		p := report.NewProgress(stderr, style)
		if isTTY(stderr) && style.Color && !*noAnim && os.Getenv("LEAKPATROL_NO_ANIM") == "" {
			p.Splash()
		}
		if all {
			// `all` promises "preflight, then every tier": print the table it would
			// otherwise take a second command to see, on the progress stream.
			preflightTable(stderr, env, style)
		}
		p.Header(scope(sub, env))
		prog = p
	}

	eng := &engine.Engine{Detectors: dets, DetectorTimeout: *tierTimeout, Progress: prog, All: all}
	rep := eng.Run(ctx, env)

	if *asJSON {
		if err := report.JSON(stdout, rep); err != nil {
			return fail("%v", err)
		}
	} else {
		report.Human(stdout, rep, report.Style{Color: useColor(*colorMode, stdout), Quiet: *quiet, Verbose: *verbose})
	}
	// The exit code answers only "did leakpatrol run"; the verdict is in the
	// report body (or --json). See model.ExitToolError.
	return 0
}

func allDetectors() []engine.Detector {
	return []engine.Detector{version.New(), deploy.New(), db.New(), fs.New(), image.New(), logs.New()}
}

// scope is the one-line header naming what this run looks at.
func scope(sub string, env *engine.Env) string {
	switch sub {
	case "deploy":
		return "asking " + env.Server
	case "db":
		return "running Coder's advisory SQL"
	case "fs":
		return fs.Scope(env.Roots)
	case "image":
		return "scanning " + strings.Join(env.Images, ", ")
	case "logs":
		return "reading " + strings.Join(env.Logs, ", ")
	case "coder-version":
		return "checking the coder CLI's version"
	}
	return "every tier it can run here"
}

func printSQL(w io.Writer, fail func(string, ...any) int, purge bool) int {
	if purge {
		body, err := db.Purge()
		if err != nil {
			return fail("%v", err)
		}
		fmt.Fprint(w, body)
		return 0
	}
	names, bodies, err := db.Queries()
	if err != nil {
		return fail("%v", err)
	}
	for i := range names {
		fmt.Fprintf(w, "-- ===== %s =====\n%s\n", names[i], bodies[i])
	}
	return 0
}

// preflightTiers evaluates readiness without running anything.
func preflightTiers(env *engine.Env) []model.Tier {
	var tiers []model.Tier
	for _, d := range allDetectors() {
		t := model.Tier{Name: d.Name(), Status: model.TierRan, MaterialGap: false}
		if r := d.Ready(env); r != "" {
			t.Status, t.Reason, t.MaterialGap = model.TierSkipped, r, d.Material()
		}
		tiers = append(tiers, t)
	}
	return tiers
}

// preflightTable prints which tiers would run here and why the others would not
// -- the coverage table before spending a minute finding out.
func preflightTable(w io.Writer, env *engine.Env, s report.Style) {
	fmt.Fprintf(w, "%s %s\n", s.Paint("dim", "preflight on"), runtime.GOOS+"/"+runtime.GOARCH)
	for _, t := range preflightTiers(env) {
		switch {
		case t.Status == model.TierRan && t.Name == "fs":
			fmt.Fprintf(w, "  %s %-13s would run: %s\n", s.Paint("good", "✓"), t.Name, fs.Scope(env.Roots))
		case t.Status == model.TierRan:
			fmt.Fprintf(w, "  %s %-13s would run\n", s.Paint("good", "✓"), t.Name)
		case t.MaterialGap:
			fmt.Fprintf(w, "  %s %-13s skipped: %s  %s\n", s.Paint("warn", "○"), t.Name, t.Reason, s.Paint("warn", "<- the verdict cannot be CLEAN without this"))
		default:
			fmt.Fprintf(w, "  %s %-13s skipped: %s\n", s.Paint("dim", "○"), t.Name, s.Paint("dim", t.Reason+" (optional)"))
		}
	}
	fmt.Fprintln(w)
}

func preflight(w io.Writer, env *engine.Env, asJSON bool, colorMode string) int {
	if asJSON {
		if err := report.RawJSON(w, map[string]any{
			"tool": "leakpatrol " + buildinfo.Version, "platform": runtime.GOOS + "/" + runtime.GOARCH,
			"server": env.Server, "token_present": env.Token != "", "dsn_present": db.DSN(env) != "",
			"fs_scope": fs.Scope(env.Roots), "tiers": preflightTiers(env),
		}); err != nil {
			return model.ExitToolError
		}
		return 0
	}
	fmt.Fprintf(w, "leakpatrol %s ", buildinfo.Version)
	preflightTable(w, env, report.Style{Color: useColor(colorMode, w)})
	return 0
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "leakpatrol %s (%s, built %s, %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date, buildinfo.GoVersion())
	fmt.Fprintln(w, buildinfo.Repo+" · "+buildinfo.Attribution+" · "+buildinfo.Advisory)
}

// coderVersionLine appends the coder CLI check to `version`, or says plainly that
// there is no CLI to check. It is information, not a verdict.
func coderVersionLine(w io.Writer) int {
	if _, err := exec.LookPath("coder"); err != nil {
		fmt.Fprintln(w, "coder CLI: not on PATH (the deploy tier reads the server's version instead)")
		return 0
	}
	out, err := exec.Command("coder", "version").Output()
	if err != nil {
		fmt.Fprintf(w, "coder CLI: `coder version` failed: %v\n", err)
		return 0
	}
	if f, ok := version.Finding("version", "coder CLI", string(out)); ok {
		fmt.Fprintln(w, f.Title+" -- patched builds: "+strings.Join(version.Patched, ", "))
	} else {
		fmt.Fprintln(w, "coder CLI: could not parse `coder version` output")
	}
	return 0
}

// isTTY reports whether w is a character device. A non-*os.File writer (a test
// buffer, a pipe) is never a TTY, which is what keeps the animated splash and
// every escape code out of captured output.
func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func useColor(mode string, w io.Writer) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isTTY(w)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `leakpatrol — Coder registry-hijack exposure check (GHSA-vx42-ghc9-gw65)

Was this Coder deployment exposed to the 2026-08-31 registry hijack, through
which path, and therefore what has to be rotated? Read-only; the only network
traffic is to the Coder server you name, in the deploy tier.

USAGE
  leakpatrol <command> [flags] [files…]        (flags go BEFORE files)

COMMANDS
  all             preflight table, then every tier that can run here; skips are listed, never hidden
  deploy          ask your Coder server's API (needs a session token: coder login, or CODER_SESSION_TOKEN)
  db              run Coder's advisory SQL via psql; --print-only to paste elsewhere; --purge prints the cleanup
  fs [dir…]       scan a host for the harvester and its traces (no dir = THIS machine's default roots, not a provisioner scan)
  image X…        scan container image tars (docker/podman save, crane, skopeo) or references
  logs F…         scan egress log exports (firewall/proxy/DNS/flow; plain, .gz, or - for stdin)
  coder-version   compare the coder CLI's version to the patched builds (informational)
  preflight       show which tiers would run here and why the others would not
  iocs            print the indicator set as JSON
  version         print this tool's version, then the coder CLI check

An explicit command that cannot run (no token, no DSN, no files) is a tool error,
not a report: it exits 1 and says why. Only 'all' tolerates skips.

EXIT CODES
  0  a scan ran and printed a report -- CLEAN, INDETERMINATE, EXPOSED or COMPROMISED
     alike. Read VERDICT in the report (or "verdict" in --json) for the finding.
  1  tool error -- bad flags, a tier that could not run, or an internal failure.
     Never used for a finding.

FLAGS
  --server URL         --token-file F      --offline
  --dsn URL            --print-only        --purge
  --roots D (rep.)     --logs F (rep.)     --image X (rep.)
  --json  --quiet  --verbose  --color auto|always|never  --no-animation
  --timeout D  --tier-timeout D  --max-file-size N  --home D

`+buildinfo.Repo+` · `+buildinfo.Attribution+`
`)
}
