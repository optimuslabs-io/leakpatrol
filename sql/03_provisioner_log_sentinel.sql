-- Coder advisory GHSA-vx42-ghc9-gw65, query 3 (verbatim except the placeholder).
-- Provisioner jobs whose logs contain the Terraform address of the harvester's
-- external data source. A hit is proof the tampered module was EVALUATED, i.e.
-- the harvester ran inside that job.
--
-- {{SENTINEL}} is substituted at runtime with the advisory's sentinel string
-- (`leakpatrol db --print-only` prints the substituted form). The literal is
-- kept out of this file so the binary that embeds it never contains an indicator
-- it hunts for and cannot flag itself.
SELECT DISTINCT
	pj.type                                 AS job_type,
	pj.id                                   AS job_id,
	wb.id                                   AS workspace_build_id,
	w.id                                    AS workspace_id,
	COALESCE(tv_import.id, tv_build.id)     AS template_version_id,
	t.id                                    AS template_id,
	t.name                                  AS template,
	COALESCE(tv_import.name, tv_build.name) AS template_version,
	w.name                                  AS workspace,
	u.username                              AS owner_or_initiator,
	pj.started_at,
	pj.job_status,
	w.deleted                               AS workspace_deleted
FROM provisioner_job_logs pjl
JOIN provisioner_jobs pj
	ON pj.id = pjl.job_id
LEFT JOIN template_versions tv_import
	ON tv_import.job_id = pj.id
LEFT JOIN workspace_builds wb
	ON wb.job_id = pj.id
LEFT JOIN template_versions tv_build
	ON tv_build.id = wb.template_version_id
LEFT JOIN workspaces w
	ON w.id = wb.workspace_id
LEFT JOIN templates t
	ON t.id = COALESCE(tv_import.template_id, tv_build.template_id, w.template_id)
LEFT JOIN users u
	ON u.id = COALESCE(w.owner_id, pj.initiator_id)
WHERE pjl.output LIKE '%{{SENTINEL}}%'
ORDER BY pj.started_at;
