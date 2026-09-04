<!-- Thanks. Every merge to main is a release, so please keep the checklist honest. -->

## What and why

<!-- One paragraph. If this changes a detector or a verdict rule, say which and why. -->

## Checklist

- [ ] `make check` passes locally (verify-deps, gofmt, vet, race tests, cross-compile).
- [ ] New behaviour has a test; invariants that this touches are tested, not just happy paths.
- [ ] No indicator appears as a readable literal in non-test source (markers stay reversed; the self-detect test passes).
- [ ] No `model.Evidence` field can carry file contents or log text.
- [ ] Networking is still linked only through `internal/detect/deploy`; `go.sum` is still empty.
- [ ] Every new finding at MEDIUM or above sets a `model.Path`; every new `Ready` gives an honest skip reason.
- [ ] Comments explain **why** a constraint exists.
- [ ] If this touches the `deploy` or `db` tier: `make lab-up` was run and reached COMPROMISED.
