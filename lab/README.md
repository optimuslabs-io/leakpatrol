# leakpatrol lab — a contained reconstruction of the Coder registry hijack

This lab stands up the actual attack, at small scale, and proves `leakpatrol`
detects it against a **live coderd** — not a fixture. A real Coder server (v2.36.3,
the release just before the patched 2.36.4), a real Postgres, a real Terraform
provider, and a rogue nginx that answers as both `registry.coder.com` (serving a
tampered module) and `www.coder-infra.com` (the exfil sink).

Pushing a template pulls the hijacked module; coderd evaluates its
`data.external.telemetry` block during the import plan; the stand-in harvester
POSTs to the sink. Then `leakpatrol` runs from a neighbour container — the way
you would scan a provisioner pod — and must reach **COMPROMISED** through the
`deploy`, `db`, and `logs` paths.

## Run it

```bash
make lab-up      # build, stand up, attack, detect, assert
make lab-down    # tear down and delete generated secrets
```

`lab-up` is idempotent. First run needs the internet **once** to mirror the
Terraform providers; every run after that is fully offline.

## How it is contained

The lab simulates an exfiltration, so containment is the design, not an add-on:

| Control | What it stops |
|---|---|
| `internal: true` network | Docker adds no gateway/NAT. Nothing in the lab can reach the internet — the "exfil" physically cannot leave this machine. |
| Compose DNS **aliases** | `registry.coder.com` / `www.coder-infra.com` resolve to the rogue container **only for lab containers**. Your host's `/etc/hosts`, DNS and trust store are never touched. |
| No published ports | Nothing on your LAN can reach the lab. Assertions run from a container **on** the lab network. |
| No Docker socket mounted | Nothing in the lab can talk to the daemon or escape to the host. |
| Digest-pinned images | A re-run cannot silently pull different bytes. |
| `cap_drop: ALL` + `no-new-privileges` | Minimal container privilege throughout. |
| Throwaway CA, mounted read-only into coderd's `SSL_CERT_FILE` only | The lab CA is never added to the host; `make lab-down` deletes it. |

The single online moment — populating `lab/mirror/` with providers — runs on a
**separate, non-internal** network before the lab proper comes up, and is its own
step for exactly that reason.

## The payload is a stand-in, on purpose

`lab/module/dlp.sh` is **not** the real harvester and carries **none** of the six
published `dlp.sh` hashes. It exfiltrates only environment-variable **names**
(never values, never file contents), so there is nothing sensitive to leak even
inside the sandbox — while still producing the `data.external.telemetry` sentinel
in the job log and the `X-CLI-Token` / `/cli/check` line in the access log that
the detector is meant to catch. The real IoC hashes live in `rules/` and the
tool's marker table; the lab does not reproduce a working weapon.

Do not "improve" the lab by swapping in a real sample or pointing its DNS aliases at
the real domain. The containment above assumes a stand-in; a real harvester inside
it would still find whatever credentials the host leaks into the container. Run the
lab in a VM you control, never on a workstation joined to a corporate domain.

## What each file is

| Path | Role |
|---|---|
| `docker-compose.yml` | the four services + the internal network and containment |
| `rogue/nginx.conf` | tampered Terraform module registry **and** exfil sink in one host |
| `module/` | the tampered `coder/aider` module + stand-in `dlp.sh` |
| `template/` | the victim template an operator pushes |
| `terraformrc`, `providers.sh`, `mirror/` | offline Terraform provider installation (air-gapped pattern) |
| `seed-query1.sql` | inserts an in-window cached-module row so advisory query 1 runs live (see FINDINGS.md) |
| `gen-tls.sh`, `tls/` | throwaway CA + server cert for the lookalike hostnames |
| `run.sh` | the driver: build → stand up → attack → detect → assert |
| `out/` | generated: the linux binary, the module tarball, the JSON reports |

Everything under `tls/`, `out/`, and `mirror/` is generated and git-ignored; the
sources above are committed.
