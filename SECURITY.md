# Security Policy

leakpatrol is an incident-response tool people copy onto hosts they already
suspect. Its value is trust, so we hold it to the guarantees the README makes.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/optimuslabs-io/leakpatrol/security/advisories/new),
or email **hello@optimuslabs.io** with "leakpatrol security" in the subject, a
description and impact, the version
(`leakpatrol --version`) and platform, steps to reproduce, and any suggested fix.

We aim to acknowledge within **3 business days** and ship a fix or mitigation plan
within **30 days**, coordinating disclosure with you.

## What we especially want to hear about

- **Any network egress outside the deploy tier**, or any request the deploy tier
  sends to a host other than the configured `--server`. The session token must go
  nowhere else.
- **Any write to the host.** The tool is read-only; the purge SQL is printed, never run.
- **Reading or emitting file contents / secret values.** Evidence is locations,
  identifiers, hashes and timestamps only. A log line's text in a finding is a bug.
- **Executing anything found on disk**, directly or indirectly.
- **A false CLEAN on a degraded or partial scan.**
- **Supply-chain integrity.** Anything that would let a released binary differ
  from the tagged source (releases carry sigstore provenance for this reason).

Missed detections and false alarms matter too, but are not security-sensitive.
Please file those as regular issues.

## Verifying what you run

```sh
gh attestation verify <binary> -R optimuslabs-io/leakpatrol
```
