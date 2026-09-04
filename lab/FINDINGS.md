# What the lab established (and what it can't)

Running `leakpatrol` against a live, contained coderd — not a fixture —
confirmed some load-bearing assumptions and drew one honest boundary. Recorded
here so the next person does not have to rediscover them.

## Confirmed against a live Coder v2.36.3

1. **`data.external` runs at template-push / plan time, with no workspace and no
   apply.** The provisioner log showed `module.aider.data.external.telemetry:
   Refreshing...` during `coder templates push`. This is the advisory's most-missed
   claim, now witnessed: *authoring or updating a template* — not only building a
   workspace — executes the harvester. The `template-import` exposure path is real.

2. **The sentinel, not the window, is what catches a compromise.** The lab runs in
   real time (well outside the 2026-08-31 07:35–21:45 UTC window), so the deploy
   tier honestly reported **"0 in window"** — and still returned **COMPROMISED**,
   off `data.external.telemetry` in the import job log. A detector that trusted the
   window arithmetic alone would have cleared this deployment. This is the live
   version of the invariant "in-window activity with empty logs is EXPOSED, not a
   negative," from the other direction: out-of-window activity with a sentinel is
   still COMPROMISED.

3. **The db tier's `psql --csv` path parses the real schema.** Query 3
   (`provisioner_job_logs.output LIKE '%data.external.telemetry%'`) returned rows
   against a genuine coderd Postgres; the DSN → `PG*` env split and CSV decode work
   outside the unit tests.

4. **The deploy client's host-pinning does not break a plain-HTTP internal
   deployment.** The lab's access URL is `http://coder:3000`; the restricted
   RoundTripper and `CheckRedirect` allowed it and refused everything else.

## db query 1 is now exercised live (was the one boundary)

Query 1 (`cached_module_files`, the module-cache view) is **window-bounded**:
`f.created_at >= '2026-08-31 07:35' AND < '2026-08-31 21:45'`. A lab that runs in
real time writes cache rows stamped "now", so query 1 returns 0 on its own —
originally the one path `LAB PASS` did not prove, covered by `internal/detect/db`
unit tests only.

`lab/seed-query1.sql` closes it. The lab's genuine cache row already carries the
exact query-1 signature (`created_by` = null UUID, `mimetype = application/x-tar`)
because a real coderd cached the tampered module; only its `created_at` is "now".
The seed inserts an in-window twin and points the latest template version's
`cached_module_files` at it, and `run.sh` then asserts `leakpatrol db` reports
`db.cached_module_in_window`. So the cache-during-window path — the one the engine
names in its own limitation line ("only the database can show a module cached
DURING the window on a version built AFTER it") — now runs end-to-end against the
real Coder schema.

Still a documented stretch: **query 2** (workspaces on a tainted version) needs a
real `workspace_latest_builds` row, which the lab does not create (no workspace is
built). Left for later.

## Operational notes (so the next run is not a debugging session)

- **First-user creation needs the API, not `coder login`.** Without a TTY, `coder
  login --first-user-*` falls through to interactive token entry. `run.sh` POSTs to
  `/api/v2/users/first` then `/login` instead — deterministic and idempotent.
- **nginx's `access.log` is a symlink to `/dev/stdout`.** Logging there never lands
  on the shared volume, and `grep` on it blocks forever. The rogue config writes to
  a real file (`lab_access.log`); the `logs` tier reads that.
- **Bind mounts go stale when `out/` is rebuilt.** `run.sh` rebuilds the binary and
  tarball every run, so it brings the stack up with `--force-recreate`; a surviving
  container would keep a mount pointing at the deleted inode and see an empty
  `/lab/bin`.

## Why this lab earns its place

The unit suite cannot run a real `terraform plan`, a real provisioner, real
`psql`, or a real Coder API. The lab is the only thing that exercises those, so it
belongs in the pre-release path for any change to the `deploy` or `db` tiers. It is
kept out of `make check` (needs Docker, ~90s) and run explicitly via `make lab-up`.
