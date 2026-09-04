# Detection rules

Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.

- [`leakpatrol.yar`](leakpatrol.yar): two YARA rules, a definitive hash rule for the six
  published harvester payloads and an indicator rule for the network and Terraform strings.
- [`sigma/`](sigma/): DNS, network-connection, proxy, and process-creation (Linux and
  Windows) rules for the same indicators.

Every rule here comes from the same indicator set as `leakpatrol iocs`. If the two ever
disagree, the tool is wrong and the fix is in `internal/scan/markers.go`.

## These are live indicators

The domain, IP, URL path and header in these files are real attacker infrastructure,
and the hashes identify real malware, transcribed from Coder's advisory
GHSA-vx42-ghc9-gw65. The Go source stores every indicator reversed so the binary cannot
flag itself. This directory has to spell them out, so:

- an `fs` scan of this repository will flag this directory, by design;
- copying these files onto a managed workstation, or pasting from them into chat or a
  ticket, can trip DLP and EDR, so defang anything a human will read;
- do not resolve, connect to, or probe the infrastructure to "verify" a rule, and do
  not fetch the payload to test the hash rule; test with the hash strings only.

See the "For researchers" section of the top-level [README](../README.md) before
deploying or testing any of this outside a lab.
