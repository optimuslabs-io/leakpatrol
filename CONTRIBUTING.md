# Contributing to leakpatrol

Thanks for helping. leakpatrol runs on possibly-compromised provisioner hosts, so it
holds itself to a few hard rules that ordinary projects don't. Most of contributing here
is understanding *why* those rules exist and not breaking them.

## The invariants (each mechanically enforced)

- **Zero third-party dependencies.** `go.sum` stays empty. `make verify-deps`.
- **Networking only in `internal/detect/deploy`**, only to the server the operator names.
  Every other package links no `net/http` / `crypto/tls`; `verify-deps` proves it.
- **Read-only.** Host reads go through `hostfs.OpenRead`. Subprocesses are `psql`,
  `coder version`, and `docker|podman|nerdctl save`. Nothing else, and never anything
  found on disk.
- **`model.Evidence` cannot hold file contents.** Locations and identifiers, never values
  or log text.
- **Markers are stored reversed.** No non-test source file spells an indicator out,
  including SQL, taglines and comments. The self-detect test will catch you.
- **A degraded scan never reports CLEAN.**

If your change needs to bend one of these, open an issue first. `AGENTS.md` has the full
architecture and the reasoning behind each rule.

## Development

```sh
make build     # ./dist/leakpatrol
make check     # what CI runs
make test      # go test -race ./...
make demo      # synthetic compromised provisioner (expect COMPROMISED)
```

> `make demo` writes a fixture with live indicator strings that can trip corporate EDR.
> Run it in a throwaway VM or container. The fixture is never committed.

## Working with a coding agent

[AGENTS.md](AGENTS.md) is the instruction file for this repository. Claude Code loads it
through `CLAUDE.md`; Codex, Cursor, Gemini CLI and most others read it directly, so an
agent started in this checkout already knows the invariants. If yours does not pick it up
automatically, open with:

```text
Read AGENTS.md in full before touching anything, and follow its "Working here as an
agent" section literally: never write an indicator as a readable literal outside a
_test.go file, never put file contents or log text in evidence, never add a
dependency, and do not commit, tag or push. Run `make check` before you tell me a
change is done, and show me its output. The task: <describe the change>.
```

Agents get two things wrong here more than anything else. They paste an indicator into
source "for clarity", which fails the build on the self-detect test. And they run
`make demo` or `make lab-up` on a machine they should not: the first writes live
indicator strings under `/tmp`, the second needs Docker and about 90 seconds.

## Before you open a PR

1. `make check` passes locally.
2. New behaviour has a test. This codebase tests its invariants, not just its happy paths.
3. Comments explain **why** a constraint exists, not what the code does.
4. If you add a detector: implement `Ready` with an honest skip reason, set a `model.Path`
   on every finding at MEDIUM or above, and never put content in evidence.

## How releases happen

Every merge to `main` that touches code runs `make check`, tags the next patch version,
builds five platforms, attests them with sigstore, and publishes a GitHub release. Nobody
picks a version by hand. Two human gates sit in front of that: branch protection requires
a code-owner review to merge, and the `release` environment requires a maintainer to
approve the publish job. Both are repository settings, not workflow text, so a fork
without them will publish on every merge. If you maintain a fork, set them up first.

## Detection gaps

A missed indicator or a false alarm is the most valuable report we get. File it as a
regular issue with the (redacted) shape of the input. Security issues: see
[SECURITY.md](SECURITY.md).

## License

By contributing you agree your contributions are licensed under the
[Apache License 2.0](LICENSE).
