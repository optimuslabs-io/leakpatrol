#!/usr/bin/env bash
# End-to-end lab driver: stand up the hijacked registry + coderd, author the
# victim template so the harvester fires, then run leakpatrol against the live
# deployment and assert it reaches COMPROMISED through the right paths.
#
# This is the real test the unit suite cannot be: a genuine coderd, a genuine
# Terraform provider, a genuine `data.external.telemetry` in a genuine provisioner
# job log, and the tampered module cached in Coder's real Postgres schema.
#
# Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
DC="docker compose"
fail() { echo "LAB FAIL: $*" >&2; exit 1; }
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
# The --json report is pretty-printed: `"verdict": "COMPROMISED"`. Pull the value
# without assuming spacing.
verdict_of() { grep -o '"verdict"[[:space:]]*:[[:space:]]*"[A-Z]*"' "$1" 2>/dev/null | grep -o '[A-Z]\{4,\}' | head -1; }

# ---- 0. Preconditions -------------------------------------------------------
command -v docker >/dev/null || fail "docker not found"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable"

# ---- 1. Build the linux binary the operator would carry into the pod --------
step "building leakpatrol (linux) for the lab"
mkdir -p out/bin out/registry out/template
arch="$(docker version -f '{{.Server.Arch}}' 2>/dev/null || echo amd64)"
( cd .. && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -o "lab/out/bin/leakpatrol" ./cmd/leakpatrol )
cp -f ../rules/coder_registry_hijack.yar out/ 2>/dev/null || true

# ---- 2. Throwaway TLS + tampered module tarball -----------------------------
step "generating lab TLS and packing the tampered module"
./gen-tls.sh
chmod +x module/dlp.sh
# The artifact the hijacked registry serves. tar of the module dir, gzipped, at
# the path nginx maps to /mod/aider.tar.gz.
tar -C module -czf out/registry/aider.tar.gz .
cp -R template/. out/template/

# ---- 3. Provider mirror (the one online step) -------------------------------
if [ ! -d mirror/registry.terraform.io ]; then
  step "populating the offline Terraform provider mirror (needs internet, once)"
  mkdir -p mirror
  # A throwaway non-internal network so `terraform providers mirror` can reach
  # registry.terraform.io. Torn down immediately after.
  docker run --rm \
    -v "$here/providers.sh:/providers.sh:ro" \
    -v "$here/mirror:/out/mirror" \
    --entrypoint sh \
    ghcr.io/coder/coder:v2.36.3 /providers.sh \
    || fail "provider mirror step failed (needs internet access this once)"
else
  echo "provider mirror already present -- skipping the online step"
fi

# ---- 4. Bring up the contained lab -----------------------------------------
# --force-recreate because out/ (the binary, the template, the tampered tarball)
# is rebuilt every run: a container that survived from a previous run would keep a
# bind mount pointing at the deleted inode and see an empty /lab/bin. Recreating
# guarantees every mount points at what we just built.
step "starting the contained lab (internal network, no egress, no published ports)"
$DC up -d --wait --force-recreate postgres rogue coder responder \
  || { $DC logs coder | tail -40; fail "lab did not become healthy"; }

# ---- 5. Author the victim template: this is what pulls + runs the module ----
step "creating the admin user and pushing the victim template (fires the harvester during plan)"
cx() { $DC exec -T coder "$@"; }
capi() { cx sh -c "curl -sS $*"; }

# The lab admin's password is generated per checkout and kept in out/ (git-ignored,
# deleted by `make lab-down` together with the database volume it unlocks). Nothing
# in the repository is a credential, however throwaway: a literal here would trip
# every secret scanner pointed at a tool that exists to find leaked credentials.
# Re-runs reuse the file so first-user creation stays idempotent.
pwfile="$here/out/admin.password"
if [ ! -s "$pwfile" ]; then
  (umask 077; head -c 24 /dev/urandom | base64 | tr -d '\n/+=' > "$pwfile")
fi
admin_pw="$(cat "$pwfile")"
[ "${#admin_pw}" -ge 16 ] || fail "could not generate the lab admin password"

# First user via the API -- deterministic and idempotent (a second run just gets
# "already created"). The interactive `coder login` cannot create it without a TTY.
capi "-X POST http://coder:3000/api/v2/users/first -H 'Content-Type: application/json' \
  -d '{\"email\":\"admin@lab.local\",\"username\":\"admin\",\"password\":\"$admin_pw\",\"trial\":false}'" \
  >/dev/null 2>&1 || true

# Mint a session token via the login API.
token="$(capi "-X POST http://coder:3000/api/v2/users/login -H 'Content-Type: application/json' \
  -d '{\"email\":\"admin@lab.local\",\"password\":\"$admin_pw\"}'" \
  | sed 's/.*"session_token":"\([^"]*\)".*/\1/')"
[ -n "$token" ] || fail "could not mint a coder session token"

# Push the template. coderd runs `terraform plan`, pulls coder/aider from the
# hijacked registry, and evaluates data.external.telemetry -> dlp.sh -> the exfil
# POST. `|| true`: a plan that errors after the data source ran is still a
# successful reconstruction -- the sentinel is already in the job log.
cx env CODER_URL=http://coder:3000 CODER_SESSION_TOKEN="$token" \
  coder templates push aidertest --directory /lab/template --yes 2>&1 | tail -6 || true

# Give the provisioner a beat to flush its logs to Postgres.
sleep 3

# ---- 5b. Seed the one condition a real-time lab cannot make on its own -------
# A module cached DURING the hijack window. Without this, advisory query 1
# (cached_module_files, window-bounded on files.created_at) returns nothing here
# and the db tier's cache-during-window path -- the subtle one only the database
# can see -- goes untested live. See lab/seed-query1.sql and lab/FINDINGS.md.
step "seeding an in-window cached module (exercises advisory query 1 live)"
$DC exec -T responder sh -c 'psql "$CODER_PG_CONNECTION_URL" -v ON_ERROR_STOP=1 -f -' < seed-query1.sql

# ---- 6. Run leakpatrol against the live deployment ----------------------
step "leakpatrol deploy -- asking the live coderd API"

set +e
$DC exec -T -e CODER_URL=http://coder:3000 -e CODER_SESSION_TOKEN="$token" \
  responder /lab/bin/leakpatrol deploy --json >out/deploy.json 2>out/deploy.err
deploy_rc=$?
set -e
cat out/deploy.err >&2 || true
deploy_verdict="$(verdict_of out/deploy.json)"
echo "deploy verdict: ${deploy_verdict:-<none>} (rc=$deploy_rc)"

step "leakpatrol db -- Coder's advisory SQL against the real schema"
set +e
$DC exec -T responder /lab/bin/leakpatrol db --json >out/db.json 2>out/db.err
set -e
cat out/db.err >&2 || true
db_verdict="$(verdict_of out/db.json)"
echo "db verdict: ${db_verdict:-<none>}"

step "leakpatrol logs -- the rogue server's access log (the exfil call)"
set +e
# Flags before files: the tool rejects a flag after a positional on purpose.
$DC exec -T responder /lab/bin/leakpatrol logs --json /lab/roguelogs/lab_access.log \
  >out/logs.json 2>out/logs.err
set -e
cat out/logs.err >&2 || true
logs_verdict="$(verdict_of out/logs.json)"
echo "logs verdict: ${logs_verdict:-<none>}"

# ---- 7. Assertions ----------------------------------------------------------
step "asserting the lab reproduced the incident"
ok=1
grep -q '"data.external.telemetry"' out/deploy.json 2>/dev/null \
  || grep -q 'sentinel' out/deploy.json 2>/dev/null \
  || { echo "  - deploy tier did not find the sentinel"; ok=0; }
[ "$deploy_verdict" = "COMPROMISED" ] || { echo "  - deploy verdict was ${deploy_verdict:-none}, wanted COMPROMISED"; ok=0; }
[ "$db_verdict" = "COMPROMISED" ]     || { echo "  - db verdict was ${db_verdict:-none}, wanted COMPROMISED"; ok=0; }
[ "$logs_verdict" = "COMPROMISED" ]   || { echo "  - logs verdict was ${logs_verdict:-none}, wanted COMPROMISED"; ok=0; }
# The seeded in-window module must surface as query 1's finding -- proof the
# cached-module-during-window path runs end-to-end, not just in unit tests.
grep -q '"db.cached_module_in_window"' out/db.json 2>/dev/null \
  || { echo "  - db tier did not report the seeded in-window cached module (advisory query 1)"; ok=0; }

if [ "$ok" = 1 ]; then
  printf '\n\033[1;32mLAB PASS\033[0m  deploy=%s db=%s logs=%s -- leakpatrol reached COMPROMISED through the deploy, db, and egress paths against a live hijacked coderd.\n' \
    "$deploy_verdict" "$db_verdict" "$logs_verdict"
else
  echo; echo "reports are in lab/out/*.json for inspection"; fail "assertions failed"
fi
