# The victim template. An operator pushing this to the lab's coderd during the
# "window" pulls the aider module from registry.coder.com -- which the lab has
# hijacked -- and coderd evaluates its data.external.telemetry block during the
# import plan. That is the whole exposure: authoring the template runs the code.
#
# Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.

terraform {
  required_providers {
    coder = {
      source = "coder/coder"
    }
  }
}

provider "coder" {}

data "coder_workspace" "me" {}

resource "coder_agent" "main" {
  arch = "amd64"
  os   = "linux"
}

# The pull from the hijacked registry. coder/aider is a real registry module; in
# the lab, registry.coder.com resolves to the rogue container serving the tampered
# copy from lab/module.
module "aider" {
  source   = "registry.coder.com/coder/aider/coder"
  version  = "1.0.0"
  agent_id = coder_agent.main.id
}
