-- Coder advisory GHSA-vx42-ghc9-gw65, remediation (verbatim).
--
-- DESTRUCTIVE. leakpatrol never executes this file; it only prints it
-- (`leakpatrol db --purge`). Run it yourself, in a transaction, after you have
-- recorded the output of queries 01-03 for your incident record -- the rows this
-- deletes are the evidence those queries return.
--
-- PRESERVE BEFORE YOU PURGE. If this incident becomes a breach notification, a
-- regulatory inquiry, an insurance claim or a legal hold, the cached module
-- tarballs and the provisioner job logs are what you will be asked to produce.
-- Export them, and the query output, to storage you control before running this,
-- and check with counsel if a preservation duty may apply. Nothing here can be
-- undone.
--
-- It clears the cached-module reference on every affected template version and
-- deletes the poisoned module tarballs from the files table. The next build of
-- those versions re-fetches modules from the (now clean) registry.
BEGIN;

CREATE TEMP TABLE identified_module_files ON COMMIT DROP AS
SELECT DISTINCT f.id
FROM files f
        JOIN template_version_terraform_values tvtv
             ON tvtv.cached_module_files = f.id
WHERE f.created_by = '00000000-0000-0000-0000-000000000000'
 AND f.mimetype = 'application/x-tar'
 AND f.created_at >= '2026-08-31 07:35:00+00'
 AND f.created_at < '2026-08-31 21:45:00+00';

UPDATE template_version_terraform_values
SET cached_module_files = NULL
WHERE cached_module_files IN (SELECT id FROM identified_module_files);

DELETE FROM files
   USING identified_module_files c
WHERE files.id = c.id;

COMMIT;
