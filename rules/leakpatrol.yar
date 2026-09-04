/*
  leakpatrol -- YARA rules for the Coder registry hijack (GHSA-vx42-ghc9-gw65)
  Copyright 2026 Optimus Labs. Apache-2.0.
  Author: Optimus Labs -- Civilizations research team

  Two rules, deliberately separate:
    * Coder_Registry_Hijack_Harvester_Hash  -- the six published SHA-256s. Definitive.
    * Coder_Registry_Hijack_Indicators      -- any two of the network / Terraform
      indicators in one file. Strong, but a human should confirm: an IoC list, a
      SIEM export, or this very file will also match.

  Usage:  yara -r rules/leakpatrol.yar /path/to/provisioner
  NOTE: this file contains the indicators as literals, so scanning the
  leakpatrol repository itself will hit on it. That is expected.
*/

import "hash"

rule Coder_Registry_Hijack_Harvester_Hash
{
    meta:
        description = "Credential harvester served from the hijacked registry.coder.com pool (dlp.sh / dlp-docker.sh), matched by SHA-256"
        author      = "Optimus Labs -- Civilizations research team"
        date        = "2026-09-03"
        reference   = "https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65"
        reference2  = "https://www.optimuslabs.io/research/briefings/coder-registry-infrastructure-hijack"
        mitre       = "T1195.002, T1552, T1567.002"
        severity    = "critical"

    condition:
        filesize < 1MB and (
            hash.sha256(0, filesize) == "7190a17c593276d7fd71c4863a4bc0b6c957ed14249288e6f64c5540e2c49398" or  // dlp-docker.sh
            hash.sha256(0, filesize) == "a7f4fa5f7e33b2a6f6488cf28444584caa449144d246b083de919162f5514247" or  // dlp.sh (common)
            hash.sha256(0, filesize) == "414d01f6072fbf05bef513e277f4c2b504a413c8e2aa5bae133a5cbc0cda9dc1" or  // dlp.sh (aider)
            hash.sha256(0, filesize) == "a64ce3038f2a501c9735abf6a1f9f04cbddbad53371cd68bec0f7510365c8ffa" or  // dlp.sh (rstudio-server)
            hash.sha256(0, filesize) == "ebbe0d2ed8cfaf9e19edb38ce44d6b407f9771b5c0813a7add27c05f66e89596" or  // dlp.sh (windows-rdp)
            hash.sha256(0, filesize) == "7ef6b8c3c976fb60b3fa22e9e294ba548d9b532e060c1323a0124a3a7a647f13"      // dlp.sh (zed)
        )
}

rule Coder_Registry_Hijack_Indicators
{
    meta:
        description = "Two or more indicators of the Coder registry hijack in one file: exfil domain, exfil IP, exfil URL path, exfil header, harvester filename, or the Terraform telemetry data source"
        author      = "Optimus Labs -- Civilizations research team"
        date        = "2026-09-03"
        reference   = "https://github.com/coder/coder/security/advisories/GHSA-vx42-ghc9-gw65"
        mitre       = "T1195.002, T1036, T1552, T1567.002"
        severity    = "high"

    strings:
        $domain   = "coder-infra.com" nocase ascii wide
        $ip       = "199.91.220.205" ascii wide
        $path     = "/cli/check" ascii wide
        $header   = "X-CLI-Token" nocase ascii wide
        $script1  = "dlp-docker.sh" nocase ascii wide
        $script2  = "dlp.sh" nocase ascii wide
        $tfblock  = /data\s+"external"\s+"telemetry"\s*\{/ ascii
        $sentinel = "data.external.telemetry" ascii wide

    condition:
        filesize < 20MB and 2 of them
}
