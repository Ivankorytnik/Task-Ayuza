-- Run only in the same isolated task_ayuza_test DB after manual Alembic upgrade.
-- Applied by the test DB administrator, not by the runtime application.
GRANT SELECT, INSERT, UPDATE ON task_ayuza.organization TO task_ayuza_runtime;
GRANT SELECT, INSERT ON task_ayuza.audit_events TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.alembic_version TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.organization, task_ayuza.audit_events TO task_ayuza_backup;
-- No owner privileges, TRUNCATE, UPDATE/DELETE on audit, or grants on Alembic writes.
REVOKE UPDATE, DELETE, TRUNCATE ON task_ayuza.audit_events FROM task_ayuza_runtime, task_ayuza_backup, PUBLIC;
REVOKE UPDATE, INSERT, DELETE, TRUNCATE ON task_ayuza.alembic_version FROM task_ayuza_runtime, task_ayuza_backup, PUBLIC;


-- M01.2 technical/auth tables: no ownership or schema privileges.
GRANT SELECT, INSERT, UPDATE ON task_ayuza.users TO task_ayuza_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON task_ayuza.sessions TO task_ayuza_runtime;
GRANT SELECT, INSERT, DELETE ON task_ayuza.login_attempts TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.users, task_ayuza.sessions, task_ayuza.login_attempts TO task_ayuza_backup;
GRANT SELECT, INSERT, UPDATE, DELETE ON task_ayuza.prelogin_limits, task_ayuza.auth_limit_events TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.prelogin_limits, task_ayuza.auth_limit_events TO task_ayuza_backup;

-- M01.3 ACL tables. Runtime has no DELETE/TRUNCATE: access ends by flags (active/revoked_at).
-- system_role_assignments is read-only for runtime: issuing system roles is M01.4.
GRANT SELECT, INSERT, UPDATE ON task_ayuza.workspaces, task_ayuza.teams,
    task_ayuza.workspace_members, task_ayuza.team_members, task_ayuza.workspace_teams,
    task_ayuza.workspace_team_access TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.system_role_assignments TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.workspaces, task_ayuza.teams, task_ayuza.workspace_members,
    task_ayuza.team_members, task_ayuza.workspace_teams, task_ayuza.workspace_team_access,
    task_ayuza.system_role_assignments TO task_ayuza_backup;

-- M01.4. Runtime holds no DDL/DELETE/TRUNCATE. setup_state is read-only for runtime: the one-time
-- first setup is a separate privileged procedure (migration role contour), not an application path.
GRANT SELECT, INSERT, UPDATE ON task_ayuza.user_mfa, task_ayuza.mfa_backup_codes,
    task_ayuza.administrative_grants TO task_ayuza_runtime;
GRANT INSERT, UPDATE ON task_ayuza.system_role_assignments TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.setup_state TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.user_mfa, task_ayuza.mfa_backup_codes, task_ayuza.administrative_grants,
    task_ayuza.setup_state TO task_ayuza_backup;

-- M02.1 work tables. Runtime has no DDL/DELETE/TRUNCATE: objects end by archived_at/active flags.
GRANT SELECT, INSERT, UPDATE ON task_ayuza.projects, task_ayuza.project_members, task_ayuza.tasks TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.projects, task_ayuza.project_members, task_ayuza.tasks TO task_ayuza_backup;

-- M02.2. Runtime has no DDL/DELETE/TRUNCATE; comment_revisions is append-only (no UPDATE).
GRANT SELECT, INSERT, UPDATE ON task_ayuza.labels, task_ayuza.project_stages, task_ayuza.project_labels,
    task_ayuza.task_labels, task_ayuza.checklist_items, task_ayuza.comments TO task_ayuza_runtime;
GRANT SELECT, INSERT ON task_ayuza.comment_revisions TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.labels, task_ayuza.project_stages, task_ayuza.project_labels,
    task_ayuza.task_labels, task_ayuza.checklist_items, task_ayuza.comments, task_ayuza.comment_revisions TO task_ayuza_backup;

-- M02.3. task_events is append-only for runtime (no UPDATE/DELETE); idempotency keys may be re-used after expiry.
GRANT SELECT, INSERT ON task_ayuza.task_events TO task_ayuza_runtime;
GRANT SELECT, INSERT, UPDATE ON task_ayuza.idempotency_requests, task_ayuza.task_access_grants TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.task_events, task_ayuza.idempotency_requests, task_ayuza.task_access_grants TO task_ayuza_backup;

-- M03.1. Runtime has no DDL/DELETE/TRUNCATE; blocker_events is append-only (no UPDATE).
GRANT SELECT, INSERT, UPDATE ON task_ayuza.task_dependencies, task_ayuza.blockers TO task_ayuza_runtime;
GRANT SELECT, INSERT ON task_ayuza.blocker_events TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.task_dependencies, task_ayuza.blockers, task_ayuza.blocker_events TO task_ayuza_backup;

-- M04.1. Runtime may queue and process outbox rows and mark its own notifications read; no DELETE/TRUNCATE/DDL.
GRANT SELECT, INSERT, UPDATE ON task_ayuza.outbox_events TO task_ayuza_runtime;
GRANT SELECT, INSERT ON task_ayuza.notifications TO task_ayuza_runtime;
GRANT UPDATE (read_at) ON task_ayuza.notifications TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.outbox_events, task_ayuza.notifications TO task_ayuza_backup;

-- M04.2. risk_checks is append-only (no UPDATE); links are soft-removed; no DELETE/TRUNCATE/DDL.
GRANT SELECT, INSERT, UPDATE ON task_ayuza.risk_register, task_ayuza.risk_task_links, task_ayuza.risk_blocker_links TO task_ayuza_runtime;
GRANT SELECT, INSERT ON task_ayuza.risk_checks TO task_ayuza_runtime;
GRANT SELECT ON task_ayuza.risk_register, task_ayuza.risk_checks, task_ayuza.risk_task_links, task_ayuza.risk_blocker_links TO task_ayuza_backup;
