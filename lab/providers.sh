#!/bin/sh
# Populate lab/mirror/ with the Terraform providers the tampered module needs,
# using Terraform's own provider-mirror command. This is the ONLY step that
# touches the internet, which is why it is a separate target run before the lab's
# internal network comes up.
#
# Runs inside the coder image (which bundles terraform) on a throwaway,
# NON-internal network, writing to the mounted mirror dir. Nothing from the lab
# proper runs here.
#
# Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.
set -eu

mkdir -p /out/mirror
cat > /tmp/providers.tf <<'EOF'
terraform {
  required_providers {
    coder    = { source = "coder/coder" }
    external = { source = "hashicorp/external" }
  }
}
EOF

cd /tmp
terraform providers mirror -platform=linux_amd64 -platform=linux_arm64 /out/mirror
echo "mirror populated:"
find /out/mirror -maxdepth 3 -type d | sed 's|/out/mirror|  mirror|'
