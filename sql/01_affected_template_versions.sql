-- Coder advisory GHSA-vx42-ghc9-gw65, query 1 (verbatim).
-- Template versions whose registry modules were cached during the serving window.
-- A hit means a template create / update / dry-run pulled from the hijacked
-- registry: the provisioner's own environment is considered leaked.
SELECT
   t.name  AS template,
   tv.name AS template_version,
   tv.id   AS template_version_id,
   f.id    AS module_file_id,
   f.created_at AS module_cached_at,
   tv.created_at AS version_created_at
FROM files f
        JOIN template_version_terraform_values tvtv
             ON tvtv.cached_module_files = f.id
        JOIN template_versions tv
             ON tv.id = tvtv.template_version_id
        JOIN templates t
             ON t.id = tv.template_id
WHERE f.created_by = '00000000-0000-0000-0000-000000000000'
 AND f.mimetype = 'application/x-tar'
 AND f.created_at >= '2026-08-31 07:35:00+00'
 AND f.created_at < '2026-08-31 21:45:00+00'
ORDER BY t.name, tv.created_at;
