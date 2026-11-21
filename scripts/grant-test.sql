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
