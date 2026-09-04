# AGENTS.md

Instructions for anyone, human or agent, working in this repository. Claude Code loads it
through `CLAUDE.md` (`@AGENTS.md`); Codex, Cursor, Gemini CLI and others read it directly.

## What this is

`leakpatrol` is a single-binary incident-response tool (Go, stdlib only) for the
Coder registry hijack, GHSA-vx42-ghc9-gw65. It answers, for a Coder operator on any OS:
was this deployment exposed, through which path, and therefore what has to be rotated.
Entry point `cmd/leakpatrol`, everything else under `internal/`. Third Optimus Labs
"patrol" after grokpatrol; same house style, same invariants.

## Working here as an agent

Read this whole file before editing. The invariants below are tested, and several are
the kind an assistant breaks by being helpful.

- **Never write an indicator as a readable literal** anywhere outside a `_test.go` file:
  not in code, SQL, comments, taglines, or docs generated into the tree. New markers go
  reversed into `internal/scan/markers.go`, and the self-detect test is extended. That test
  builds the binary and greps it; a forward literal fails the build.
- **Never put content in evidence.** No file bytes, log text or env values, not even for
  debugging. `internal/report/leak_test.go` plants secrets and fails if one is printed.
- **Never add a dependency**, however small. `go.sum` stays empty (`make verify-deps`).
- **Generated, never committed, not worth reading:** `dist/`, `lab/out/`, `lab/tls/`
  (a throwaway CA and private key), `lab/mirror/` (a 25 MB Terraform provider cache), and
  `/tmp/leakpatrol-fixture*`. `.claude/settings.json` denies Claude Code reads of the
  in-repo ones; other agents should treat this list the same way.
- **`make demo` writes live indicator strings under `/tmp`** and can trip EDR on a managed
  machine. CI runs it. `make lab-up` needs Docker and about 90 s; run it only when a change
  touches the `deploy` or `db` tier.
- **Never touch the real infrastructure or payload.** The indicators are live attacker
  assets. Do not resolve, `curl`, or probe the exfil domain, IP or path to "check whether
  it is still up", and do not download a sample by hash from any malware platform. Test
  with the strings and hashes only; the lab uses a safe stand-in for exactly this reason.
- **Do not commit, tag or push unless asked.** Every code merge to `main` publishes a
  signed release automatically.

## Commands

```sh
make build       # ./dist/leakpatrol
make check       # unit gate: verify-deps + gofmt + vet + race tests + cross-compile smoke
make test        # go test -race ./...
make demo        # synthetic compromised provisioner -- ASSERTS VERDICT: COMPROMISED, exits 1 otherwise
make demo-clean  # empty fixture -- ASSERTS VERDICT: CLEAN
make release     # five platforms + SHA256SUMS (runs verify-deps first)
```

Single test: `go test -run <Name> ./internal/<pkg>/`. `TestCompiledBinaryDoesNotContainItsOwnMarkers`
builds a real binary and skips under `-short`.

CI runs `make check`, then `make demo` + `make demo-clean` as a separate end-to-end verdict gate
(kept separate so an EDR-driven fixture skip is visible, not folded into the unit gate), then an
alpine job that runs a real `all --offline --json` scan — not just preflight — in Coder's own base image.

### Test layout

`cmd/leakpatrol/main_test.go` drives `run(args, stdout, stderr, stdin)` in-process; that
signature exists so CLI contracts (every false-CLEAN refusal, flags-after-files, missing-tar) are
testable without `os/exec`. `execCLI` clears `CODER_URL`/`CODER_SESSION_TOKEN`/`CODER_CONFIG_DIR`/
`CODER_PG_CONNECTION_URL` so a developer's real `coder login` can never make tests hit the network.
`internal/detect/db` and `internal/detect/image` tests install fake `psql`/`docker` on `PATH` —
the db one asserts the DSN password reaches `PG*` env and never argv. `internal/report/leak_test.go`
plants secrets in every writable report string and fails if any reaches human/JSON/progress output.

## Invariants (each mechanically enforced)

- **Zero third-party deps.** `go.sum` empty. `make verify-deps`.
- **Networking only in `internal/detect/deploy`.** No other package may link `net/http` or
  `crypto/tls`; `verify-deps` checks `go list -deps` per package. The deploy client's
  `restricted` RoundTripper and `CheckRedirect` refuse any host but `--server`'s. `net/url`
  (no sockets) is fine anywhere.
- **Read-only.** All host reads via `hostfs.OpenRead`. Subprocesses: only `psql`
  (read-only queries on stdin), `coder version`, `docker|podman|nerdctl save`. Never execute
  anything found on disk. The purge SQL is printed, never run.
- **`model.Evidence` has no field that can hold file contents.** Locations, identifiers,
  hashes, timestamps, tool-authored prose. Log OUTPUT text never reaches a finding — only a
  line number / log id. Tests grep every output channel.
- **Markers are stored reversed, flipped at init** (`internal/scan/markers.go`). No non-test
  source may contain an indicator as a readable literal — including `sql/03_*.sql`, which
  carries `{{SENTINEL}}` and is substituted at runtime, and the logo taglines. The self-detect
  test builds the binary and greps it (lower-cased) for every text marker and payload filename.
- **A degraded scan never reports CLEAN — but skips are coverage, not verdict.** Material
  `ScanError` → `Report.Degraded`. In `all` mode only a skipped tier whose `Material()` is
  true degrades (deploy: no credentials / `--offline`); a missing image tar, flow-log export,
  psql or coder CLI is a COVERAGE line, never an INDETERMINATE. When deploy ran and db did
  not, the engine adds the one limitation only db can close (`cached_module_files`). LOW-only
  findings → INDETERMINATE.
- **Missing logs are not negatives.** Coder drops provisioner logs. An in-window job whose
  log 404s keeps its MEDIUM finding and adds a material `missing-log` error ("execution cannot
  be excluded"); out-of-window 404s are counted only. The deploy tier judges in-window with a
  ±15 min clock-skew pad (`deploy.clockSkew`); Coder's SQL stays verbatim.
- **Exit code answers "did it run", never "what did it find."** 0 = report produced. 1 = tool error —
  and an explicit single-tier command whose `Ready()` fails IS a tool error (main refuses to run it;
  engine additionally forces INDETERMINATE when zero tiers ran). Positionals starting with `-` are
  rejected (Go's `flag` stops at the first non-flag). `image` never falls through to `docker save`
  for something that looks like a path. `--token-file` that cannot be read is an error.
- **The tier is `coder-version`, never `version`.** `leakpatrol version` prints the tool version
  plus the coder CLI check, kubectl-style; a scan-shaped CLEAN under that word was misread as a scan.
- **REMEDIATE only on EXPOSED/COMPROMISED; INDETERMINATE gets NEXT.** ROTATE is scoped by where the
  findings came from (`report.scopeOf`): deploy/db → provisioner (+ owners if a build), fs/image →
  that host, logs egress → whatever made the connection. Progress marks: green ✓ only for a genuine
  empty result; `!` hits, `✗` failed, `?` weak.
- **Fixtures are generated, never committed** (`testdata/make_fixture.sh`, in-test builders).
  `rules/` necessarily contains literal IoCs — it is excluded from nothing, and a `fs` scan
  over this repo will flag it. That is honest.

### Verdicts (`engine.verdict`, in order)

- **COMPROMISED** — finding ≥ HIGH tagged `executed` or `egress` (sentinel in a job log,
  exfil call in a shell history, hit in an egress log).
- **EXPOSED** — any finding ≥ MEDIUM (in-window template version / build, telemetry block or
  hash on disk / in image, indicator in a module tree or a text file).
- **INDETERMINATE** — nothing ≥ MEDIUM, but degraded (material error, or deploy skipped in
  all-mode) or a LOW (filename-only) finding.
- **CLEAN** — none of the above.

Severity: INFO (version) < LOW (filename only) < MEDIUM (pulled in window; reference hit) <
HIGH (payload hash, telemetry block, module-tree indicator) < CRITICAL (sentinel, egress, history).

### Exposure paths (`model.Path`) drive ROTATE

`template-import` (provisioner env), `workspace-build` (+ owner OIDC/SSH/external-auth),
`present` (on this host), `executed`, `egress`. `report.rotate` renders per path.

## Architecture

`engine.Engine` runs `Detector`s sequentially; each declares `Ready(env)` (skip reason) and
`Run`. Panics are recovered per tier. `Progress` narrates on stderr (never stdout).

| Package | Role |
|---|---|
| `scan` | reversed markers, line matcher, telemetry regexes, payload hashes |
| `hostfs` | only filesystem access; walker never follows symlinks or crosses mounts |
| `detect/inspect` | ONE judgement function for a file's name+bytes, shared by `fs` and `image`; `Collector` groups matches into findings |
| `detect/fs` | walks roots (per-OS defaults in `hostfs.DefaultRoots`) in **two passes**: pass 1 reads only files `inspect.EagerRead` accepts (harvester name, `*.tf`, shell history, `.terraform`/`modules`/`terraform.d`/`coder-provisioner` trees) — all HIGH/CRITICAL if they fire; pass 2 runs **only if pass 1 found nothing ≥ HIGH** and sweeps the rest (text markers, plus hashing any leftover ≤ `hashSizeBand` to catch a renamed payload). The skip is stated in LIMITATIONS and the summary. |
| `detect/image` | `archive/tar` over docker-save / OCI layouts, nested gz layers, stdin, or `<cli> save` |
| `detect/logs` | line scan over files/stdin, gzip-aware |
| `detect/deploy` | Coder `/api/v2`: templates → versions → version logs; workspaces → builds(since window) → build logs; `/buildinfo` version |
| `detect/db` | embedded `sql/` via `psql --csv` (DSN split into `PG*` env, never argv); `--print-only`, `--purge` |
| `detect/version` | tier `coder-version`: `coder version` + `IsPatched` |
| `iocs` | JSON export, forward strings assembled at runtime |
| `report` | `logo.go` (glitch-reveal wordmark), `progress.go`, `human.go`, `json.go` |

Coder API facts relied on (verified against coderd's router, and end-to-end against a
live coderd v2.36.3 — see `lab/`): `GET /api/v2/templates`,
`/templates/{id}/versions?include_archived&limit&offset`, `/templateversions/{id}/logs`,
`/workspaces?q&limit&offset`, `/workspaces/{id}/builds?since`, `/workspacebuilds/{id}/logs`,
`/buildinfo`; header `Coder-Session-Token`; CLI login files at `<UserConfigDir>/coderv2/{url,session}`.

## Lab (`lab/`, `make lab-up`)

A contained, egress-less Docker reconstruction: a real coderd + Postgres, a rogue nginx
serving a tampered `coder/aider` module as `registry.coder.com` and receiving exfil as
`www.coder-infra.com`, and a template push that fires the harvester during `terraform plan`.
`leakpatrol` then runs from a neighbour container and must reach COMPROMISED via the
`deploy`, `db`, and `logs` paths. Kept out of `make check` (needs Docker, ~90s); **run it
before releasing any change to the `deploy` or `db` tiers** — it exercises real `psql`, a real
Terraform provider, and the real API, which the unit suite cannot. `lab/FINDINGS.md` records
what running it established. `lab/seed-query1.sql` inserts an in-window cached-module row so
advisory query 1 (`cached_module_files`, window-bounded) runs live too; the remaining stretch is
query 2 (needs a workspace build). The lab payload is a safe stand-in whose hash matches none of
the six published IoCs.

## Conventions

- Comments explain *why* a constraint exists. Preserve that reasoning on guarded paths.
- Colour is semantic (red act / yellow exposure / green good / cyan location / dim context).
- Attribution "Optimus Labs · Civilizations research team" appears in NOTICE, README, the
  logo subtitle, `--version`, `--json` `tool.author`, `iocs` `curated_by`, YARA/Sigma `author`,
  and every `.go` SPDX header. Keep them consistent (`buildinfo.Attribution`).
