-- Reconstruct the one condition a real-time lab cannot produce on its own: a
-- registry module CACHED DURING the hijack window (2026-08-31 07:35-21:45 UTC).
--
-- The lab's genuine cache row already carries the exact query-1 signature --
-- created_by = the null UUID (system), mimetype = application/x-tar -- because a
-- real coderd cached the tampered module. The only thing it cannot have is an
-- in-window created_at, since the lab runs today. So insert an in-window twin and
-- point the latest template version's cached_module_files at it. This makes
-- advisory query 1 (sql/01_affected_template_versions.sql) and the db tier's
-- db.cached_module_in_window finding fire against the real Coder schema -- the one
-- path FINDINGS.md records as unit-tested only.
--
-- Copyright 2026 Optimus Labs (Civilizations research team). Apache-2.0.

BEGIN;

INSERT INTO files (id, hash, created_by, created_at, mimetype, data)
VALUES (
  'deadcafe-0000-4000-8000-00000000c0de',
  'deadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafe', -- 64-char, unique
  '00000000-0000-0000-0000-000000000000',                            -- the null UUID query 1 keys on
  '2026-08-31 12:00:00+00',                                          -- inside the window
  'application/x-tar',
  decode('00', 'hex')                                                -- bytea not null; content is irrelevant to query 1
)
ON CONFLICT (id) DO NOTHING;

-- Point the newest template version's cached-module pointer at the in-window twin.
UPDATE template_version_terraform_values
SET cached_module_files = 'deadcafe-0000-4000-8000-00000000c0de'
WHERE template_version_id = (
  SELECT id FROM template_versions ORDER BY created_at DESC LIMIT 1
);

COMMIT;
