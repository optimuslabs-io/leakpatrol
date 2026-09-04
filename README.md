# leakpatrol

[![CI](https://github.com/optimuslabs-io/leakpatrol/actions/workflows/ci.yml/badge.svg)](https://github.com/optimuslabs-io/leakpatrol/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/optimuslabs-io/leakpatrol)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/optimuslabs-io/leakpatrol)](go.mod)
![Dependencies: zero](https://img.shields.io/badge/dependencies-0-brightgreen)
![Provenance: sigstore](https://img.shields.io/badge/provenance-sigstore-blue)

Tells a Coder operator whether their deployment was exposed to the 2026-08-31
registry hijack ([GHSA-vx42-ghc9-gw65](https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65),
rated Critical, CVSS v4 9.0, by Coder), through which path, and therefore what to rotate.

By the Civilizations research team at Optimus Labs. The analysis behind it is our
briefing, [*When the Supply-Chain Attack Has No CVE: Inside the Coder Registry Hijack*](https://www.optimuslabs.io/research/briefings/coder-registry-infrastructure-hijack).

Optimus Labs is not affiliated with, endorsed by, or acting for Coder Technologies, Inc.
Coder is their trademark, used here only to name the product this tool inspects. The
authoritative source on the incident is Coder's advisory; this tool implements it.

> **What happened.** For ~14 hours (07:35–21:45 UTC, Aug 31) an attacker controlled
> Coder's Cloudflare pool for `registry.coder.com` and served tampered modules
> carrying a credential harvester. Any template create/update/dry-run, or any
> workspace build with module caching disabled, pulled it. It ran inside your
> provisioner and shipped cloud, AI-tooling, CI/CD, Git and SSH credentials to a
> lookalike domain. There is no CVE, no bad
> version to pin away from, and nothing in NVD/OSV/VirusTotal. Exposure is scoped
> by activity in the window, not by version, so you have to look at your own logs.

## Install

Download a binary from [releases](https://github.com/optimuslabs-io/leakpatrol/releases)
(`linux`/`darwin` × `amd64`/`arm64`, `windows/amd64`) and verify that it was built by this
repository's release workflow before you run it anywhere that matters:

```sh
gh attestation verify leakpatrol_* -R optimuslabs-io/leakpatrol
```

Or build from source with `go install github.com/optimuslabs-io/leakpatrol/cmd/leakpatrol@latest`.

The installer is for when you need the binary on a host in a hurry. It checks the download
against `SHA256SUMS`, which catches corruption but not a compromised release, so read it
first; it is short and lives at a stable path in this repository for that reason:

```sh
curl -fsSL https://raw.githubusercontent.com/optimuslabs-io/leakpatrol/main/install.sh | sh
```

One static binary with zero dependencies. It runs unchanged in Coder's own `alpine` image.

## Run

```sh
leakpatrol all
```

`all` runs a preflight, then every tier it can. With a `coder login` on the machine it
reaches your deployment automatically; with `CODER_PG_CONNECTION_URL` and `psql` it
also runs Coder's advisory SQL. The verdict is judged on the tiers that ran, and
names the ones that did not. `fs` with no roots scans this machine's default
locations, which is only a provisioner scan if this machine is the provisioner.
Copy the binary to the provisioner host or pod and run `fs /` there.

| Tier | What it checks | Needs | Works from |
|---|---|---|---|
| `deploy` | Your Coder server's API: template versions and workspace builds whose jobs ran in the window; the sentinel `data.external.telemetry` in their provisioner logs | `--server` (or `CODER_URL` / coder login) + `CODER_SESSION_TOKEN` (or coder login) | Any OS, nothing installed. The universal tier. |
| `db` | Coder's verbatim advisory SQL (queries 1–3): module-cache entries in the window, workspaces on those versions, sentinel in job logs. Authoritative | `--dsn` or `CODER_PG_CONNECTION_URL`, and `psql` on PATH; else `--print-only` and paste into any client | Admin workstation, bastion, `kubectl exec` |
| `fs` | Provisioner hosts / pods / workspaces: the harvester by SHA-256 and name, the Terraform `data "external" "telemetry"` block, exfil indicators in shell histories and module caches | read access | The suspect host itself |
| `image` | Container image tars (`docker`/`podman`/`nerdctl save`, `crane export`, `skopeo`) or references, layer by layer, without extracting | a tar, `-` (stdin), or a container CLI | Anywhere the image is |
| `logs` | Firewall / proxy / DNS / VPC-flow exports, any format, plain or `.gz`, files or stdin: the exfil domain, IP, URL path and header. Proof that data left | log retention back to Aug 31 07:35 UTC | Wherever your logs are |
| `coder-version` | `coder` CLI vs patched builds (2.37.0, 2.36.4, 2.35.7, 2.34.9). Informational | `coder` on PATH | — |

**CLI contract:** an explicit command that cannot run is a tool error (exit 1), not a report:
`deploy` with no token, `db` with no DSN, `image`/`logs` with no files, a tar path that does not
exist. It never prints a verdict. Only `all` tolerates skips, and it lists every one under
COVERAGE. Flags go before files (`leakpatrol logs --json fw.log`).

`deploy` reads a Coder deployment with a session token and `db` reads its database. Run
them only against systems you own or have written authorisation to inspect. The tool is
read-only, but that does not make the access yours.

### Per platform

```sh
# Bare host / VM (provisioner or coderd)
leakpatrol all

# Kubernetes provisioner pod (alpine image, no shell tooling needed)
kubectl cp leakpatrol_linux_amd64 coder/coder-provisioner-0:/tmp/rp
kubectl exec -n coder coder-provisioner-0 -- /tmp/rp fs / --json

# Docker / Podman host
docker save myregistry/coder-provisioner:latest | leakpatrol image -

# Windows provisioner
.\leakpatrol.exe all

# Logs only (security analyst, no Coder access)
zcat fw-2026-08-31*.log.gz | leakpatrol logs -
aws logs tail /vpc/flow --since 2026-08-31T07:35:00Z --format short | leakpatrol logs -

# Database only, no psql here: print the SQL and paste it anywhere
leakpatrol db --print-only
kubectl exec -n coder deploy/coder-postgres -- psql -U coder --csv < <(leakpatrol db --print-only)
```

Progress narrates on stderr (green ✓ only for a genuine empty result, red `!` for hits, yellow `✗` for a tier that failed). The report goes to stdout, so `leakpatrol all --json | jq .verdict` just works.
`--offline` guarantees no network connection at all.

## Reading the verdict

A verdict is what this tool could establish from the inputs it was given, on the day it
ran, against the indicators Coder has published. It is not a certification that a
deployment is clean, a substitute for your own incident response, or legal or compliance
advice. CLEAN means the tiers that ran found none of the published indicators in what they
could read; it says nothing about evidence that has since been purged, rotated, or
recycled, or about indicators nobody has published yet. Treat the report as one input
to an investigation you own. The [Limitations](#limitations) section is part of the verdict.

| Verdict | Meaning | Do |
|---|---|---|
| **COMPROMISED** | The harvester ran (sentinel in a job log, exfil call in a shell history) or data left (egress hit) | Rotate everything in ROTATE, now |
| **EXPOSED** | The tampered module was pulled (job in window) or is present (hash or telemetry block on disk or in an image), with no proof it ran | Treat as if it ran; rotate |
| **INDETERMINATE** | Nothing found, but the deployment itself was not asked (`deploy` skipped: no credentials / `--offline`), something material could not be read, or only a weak (filename-only) signal | Log in / pass `--server`; read BLIND SPOTS |
| **CLEAN** | Nothing found by the tiers that ran, and nothing material was missing. Optional tiers you had no input for (`image`, `logs`, `db`, `version`) are listed under COVERAGE, not held against the verdict | Keep the report; run `logs`/`db` as exports and access arrive |

**Skips are coverage, not verdict.** Only a missing `deploy` degrades. A laptop without `psql`, an image tar or a flow-log dump still gets an honest CLEAN with a COVERAGE table under it. When `deploy` ran and `db` did not, the report says exactly what only the database can see: a module cached *during* the window on a version built *after* it.

**Missing logs are not negatives.** Coder drops provisioner logs, so an in-window job whose log is gone stays EXPOSED and is flagged "execution cannot be excluded". In-window checks pad the window ±15 min for provisioner clock skew.

The exposure path on each finding drives the ROTATE section:

- **template-import** → the provisioner's own environment: AWS/GCP/Azure keys, `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`, CI/CD and registry credentials, Terraform variables, plus the Coder DB password if the provisioner runs inside coderd.
- **workspace-build** → all of the above plus each affected owner's OIDC token, SSH key, and GitHub/GitLab/Bitbucket external-auth tokens.
- **present / executed / egress** → everything on that host: env, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.npmrc`, `.env`, shell history.

Then: `leakpatrol db --purge` prints Coder's cleanup transaction (never executed by this tool);
clear on-disk module caches or recycle provisioner pods; upgrade to a patched build.

Before you purge anything, preserve it. The cached module tarballs, the provisioner job
logs and the egress logs are the evidence of what happened, and if this incident becomes
a breach notification, a regulatory inquiry, an insurance claim, or a legal hold, you will
be asked for them. Export the query output and the artefacts to storage you control, in a
form you can attest to, and check with counsel before running anything destructive. The
purge SQL deletes the very rows the advisory queries return.

### Sweeping something huge with ripgrep

`fs` reads in parallel and drops binaries after an 8 KB sniff, so it is within a
small factor of ripgrep on real trees while also hashing payloads and grading hits by
location. If you still want `rg` for a first pass over a very large share or archive,
the flags matter. Use `-uuu`, because ripgrep otherwise skips hidden files and
gitignored trees, which is exactly `.terraform/` and `.bash_history`. Use `-l` as
well: a history line *is* the exfil command, so never print the matching line.

```bash
rg -uuu -l -i -e 'coder-infra\.com' -e '199\.91\.220\.205' -e '/cli/check' -e 'x-cli-token' -e 'data\.external\.telemetry' /path | xargs -r leakpatrol fs
```

## Using it with an AI agent

`leakpatrol` is built to be driven by an agent as much as by a person. `--json` is the
full report with a stable shape, exit codes mean "did it run" and never "what did it
find", and the report contains no secrets by construction, so it is safe to put in an
agent's context. If you are handing the incident to Claude Code, Codex, Cursor or a
similar tool on the machine where you are doing the response, paste this to get started:

```text
I am responding to the Coder registry hijack (GHSA-vx42-ghc9-gw65) and need to know
whether this deployment was exposed, through which path, and what to rotate. Use
leakpatrol (https://github.com/optimuslabs-io/leakpatrol); install it with the
install.sh from that repository if it is not on PATH. Rules:

1. Run `leakpatrol all --json` first. If it exits 1 that is a tool error, not a
   result: show me the stderr, fix the cause, and re-run. Never treat a missing
   report as CLEAN.
2. From the JSON, tell me the verdict, every finding with its severity and exposure
   path, and which tiers ran, were skipped, or failed, and why.
3. For each skipped tier, tell me exactly what would close it (a `coder login` or
   CODER_SESSION_TOKEN, a Postgres DSN, an image tar, an egress-log export) and the
   command to run once I have it. If deploy was skipped, say so first: the verdict
   is INDETERMINATE until the deployment itself has been asked.
4. If the verdict is EXPOSED or COMPROMISED, turn the ROTATE section into a checklist
   scoped to the exposure paths that were actually found.
5. Never print file contents, log lines, tokens, DSNs or session tokens, and never
   paste them into a prompt or a ticket; the report omits them on purpose. Never
   execute the SQL from `leakpatrol db --purge` or any other SQL; the tool prints it
   for a human to review and run.
6. Do not install anything else, do not modify files on this host, and do not send
   the report or any of its contents anywhere other than back to me.
```

The prompt leans on two guarantees. The session token only goes to the server you name,
and `verify-deps` proves nothing else in the binary can open a socket, so an agent
running `deploy` is not a new exfil path. `leakpatrol iocs` prints the indicator set as
JSON, so an agent writing a detection for your SIEM pulls the exact strings and hashes
from the tool instead of retyping them from an advisory.

## Indicators

`leakpatrol iocs` prints the full set as JSON. `rules/` holds the same as
[YARA](rules/leakpatrol.yar) (hash rule + indicator rule) and
[Sigma](rules/sigma/) (DNS, network, proxy, process-creation for Linux and Windows).

| | |
|---|---|
| Window | 2026-08-31 07:35 → 21:45 UTC |
| Exfil | `www[.]coder-infra[.]com` · `199.91.220[.]205` · `POST /cli/check` · header `X-CLI-Token` |
| Payloads | `dlp-docker.sh` `7190a17c…e2c49398` · `dlp.sh` ×5 (`a7f4fa5f…`, `414d01f6…`, `a64ce303…`, `ebbe0d2e…`, `7ef6b8c3…`), full hashes in `iocs` |
| Sentinel | `data.external.telemetry` in provisioner job logs; `data "external" "telemetry"` in `.tf` |
| ATT&CK | T1583.001 · T1584 · T1078 · T1195.002 · T1553 · T1036 · T1059.004 · T1552 · T1567.002 |

**On module scope.** The advisory publishes a separate harvester build for `aider`,
`rstudio-server`, `windows-rdp` and `zed`, plus a `common` build. That is strong evidence
those four modules were served tampered, and a reasonable place to look first. It is not a
list of tampered modules, and the advisory does not publish one. The common build is the
reason to treat the four as a starting point rather than a boundary: it is what shipped in
modules that got no bespoke build. `leakpatrol` detects on payload hashes, the telemetry
block and the network indicators, never on a module name, so no tier is scoped to those four.

Unrelated: MalwareBazaar's `dvr.sh` / `dlr.spc` from the same week. The tool grades a filename-only match as *weak* for this reason. A hash match is definitive.

## For researchers: these indicators are live

Everything in the table above, in `rules/`, and in `leakpatrol iocs` describes real
attacker infrastructure and real malware. Treat it that way:

- **Do not touch the infrastructure.** Do not resolve, browse, `curl`, port-scan or
  "check whether it is still up" the exfil domain, the IP, or the `/cli/check` path from
  any network you care about. It tells the attacker someone is looking, it can get your
  egress IP flagged or blocked, and it will light up your own EDR and proxy logs with the
  exact pattern this tool hunts for. Use passive DNS and threat-intel platforms instead.
- **Do not fetch the payload.** The six SHA-256s identify a working credential harvester.
  `leakpatrol` contains no sample and no fixture reproduces one. If your research needs
  the binary, obtain it through a malware-sharing platform under its terms, and handle it
  as live malware: an isolated VM with no network, a snapshot to roll back to, never on a
  machine that holds credentials.
- **The strings alone can trip controls.** `rules/`, `iocs` output, and the `make demo`
  fixture carry the indicators as forward literals. Pasting them into a ticket, chat, or a
  commit on a managed machine can trigger DLP, EDR, or a content filter, and may read as a
  policy violation before anyone reads the context. Defang them (`coder-infra[.]com`,
  `199.91.220[.]205`) anywhere a human will read them, and keep the fixture in a VM.
- **Test in a controlled environment.** `make demo` writes live indicator strings to
  `/tmp`; `make lab-up` reconstructs the attack with a safe stand-in on an egress-less
  Docker network. Both are designed to be harmless. Run them in a throwaway VM or
  container you control, never on a workstation joined to a corporate domain. Never point
  the lab at the real domain or swap its stand-in for a real sample.
- **Only scan what you are authorised to scan.** The `deploy` tier uses a session token
  to read someone's Coder deployment, and `db` reads their database. Have written
  authorisation before running either against a system you do not own; this tool is
  read-only, but the access is not yours to take.
- **If you find the real thing**, report the sample and any new infrastructure to Coder
  through the [advisory](https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65)
  and to the hosting provider's abuse contact. Do not attach a payload or live URL to a
  public issue here; use the private channel in [SECURITY.md](SECURITY.md).

## Trust

This is a tool you copy onto hosts you already suspect, built for a supply-chain attack. So:

- **No telemetry, no phone-home, no update check.** The binary opens no connection you did not ask for; it cannot, because only the `deploy` tier links networking, and that tier talks only to the server you name.
- **Zero third-party dependencies.** `go.sum` is empty; `make verify-deps` fails otherwise.
- **Network only to the server you name, only in `deploy`.** `net/http` may be linked solely through `internal/detect/deploy`; every other package, including all the ones that run on a suspect provisioner, links no networking at all, and `verify-deps` proves it. The client refuses any other host and any cross-host redirect, so a session token can only go back where it came from.
- **Read-only.** All host reads go through `hostfs.OpenRead` (`O_RDONLY`). The only subprocesses are `psql`, `coder version`, and `docker|podman|nerdctl save`. Nothing found on disk is ever executed.
- **Never prints file contents.** Evidence is locations, identifiers, hashes and timestamps. The harvester stole secrets out of files; a report about it must not reproduce them.
- **Cannot flag itself.** Indicators are stored reversed and assembled at init; a test builds the binary and greps it.
- **A degraded scan is never CLEAN.** A skipped `deploy`, an unreadable root you asked for, a rejected token, a vanished in-window log → INDETERMINATE (or the EXPOSED it already was). Optional inputs you didn't have are coverage lines, not a downgrade.
- **Exit code says only whether it ran** (0) or failed as a tool (1). A tier that could not run *is* a tool failure. There is no path to `VERDICT: CLEAN` that did not look.
- **Signed, reproducible releases.** Sigstore provenance, `-trimpath`, `SOURCE_DATE_EPOCH`.

## Limitations

- It sees what is still there. A purged module cache, rotated logs, or a recycled pod leave no trace, and none of that undoes a credential that already left.
- Indicators are vendor-attested: the hashes, domain, IP, URL path, header, sentinel and window are transcribed from the advisory, not derived by us. No third party has independently reproduced them; for a 14-hour, pull-based, vendor-infrastructure attack that is the expected state, not an all-clear. Which modules were tampered with is the one thing the advisory does not enumerate, so the tool never scopes by module name.
- `deploy` cannot enumerate template dry-run jobs, and cannot see whether module caching was disabled; the `db` tier can. Use an owner token for full visibility.
- `logs` matches text. A log that stores the destination only encoded, or DNS answers without the queried name, will not match. Single-line JSON exports over 4 MiB must be split (`jq -c '.[]'`).

## Develop

```sh
make build       # ./dist/leakpatrol
make check       # unit gate: verify-deps + gofmt + vet + race tests + cross-compile smoke
make demo        # synthetic compromised provisioner -- fails unless VERDICT: COMPROMISED
make demo-clean  # empty fixture -- fails unless VERDICT: CLEAN
make lab-up      # live end-to-end vs a real, contained, hijacked coderd (needs Docker)
make lab-down    # tear the lab down and delete its generated secrets
```

Both demos assert their verdict and exit non-zero on the wrong one, so a detection regression
fails the build instead of printing a friendly wrong answer. CI runs them on every push.

`make lab-up` stands up an egress-less Docker reconstruction of the incident: a real coderd, a
rogue registry serving a tampered module, and an exfil sink. It asserts `leakpatrol` reaches
COMPROMISED through the `deploy`, `db`, and `logs` paths against the live server. Run it
before releasing any change to the `deploy` or `db` tiers, because it exercises real `psql`, a
real Terraform provider, and the real API, which unit tests cannot. See [lab/README.md](lab/README.md)
for containment details and [lab/FINDINGS.md](lab/FINDINGS.md) for what it establishes.

> `make demo` generates a fixture with live indicator strings that can trip corporate
> EDR. Run it in a throwaway VM or container. The fixture is never committed.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [AGENTS.md](AGENTS.md) for the architecture and the invariants (it is also the instruction file coding agents load).

## License

Apache-2.0. Copyright 2026 Optimus Labs. Built by the Civilizations research team, see [NOTICE](NOTICE).
