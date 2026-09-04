-- Coder advisory GHSA-vx42-ghc9-gw65, query 2 (verbatim).
-- Workspaces whose latest build uses a template version from query 1. Their
-- owners' OIDC token, SSH key and external-auth tokens passed through the
-- provisioner alongside the tampered module.
SELECT
   w.name AS workspace,
   u.username AS owner,
   wlb.transition,
   wlb.job_status,
   wlb.created_at
FROM workspace_latest_builds wlb
        JOIN workspaces w ON w.id = wlb.workspace_id
        JOIN users u ON u.id = w.owner_id
WHERE wlb.template_version_id IN (
   SELECT tvtv.template_version_id
   FROM files f
            JOIN template_version_terraform_values tvtv
                 ON tvtv.cached_module_files = f.id
   WHERE f.created_by = '00000000-0000-0000-0000-000000000000'
     AND f.mimetype = 'application/x-tar'
     AND f.created_at >= '2026-08-31 07:35:00+00'
     AND f.created_at < '2026-08-31 21:45:00+00'
)
ORDER BY w.name;
