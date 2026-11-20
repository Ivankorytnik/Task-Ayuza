"""M01.2 authentication; no administrative HTTP API.

Revision ID: 0002_m01_auth
Revises: 0001_m01_foundation
"""
from alembic import op

revision = '0002_m01_auth'
down_revision = '0001_m01_foundation'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
    CREATE TABLE task_ayuza.users (
        id uuid PRIMARY KEY,
        organization_id uuid NOT NULL REFERENCES task_ayuza.organization(id),
        login varchar(64) NOT NULL,
        login_normalized varchar(64) COLLATE "C" NOT NULL,
        display_name varchar(200) NOT NULL,
        password_hash text NOT NULL,
        active boolean NOT NULL DEFAULT true,
        must_change_password boolean NOT NULL DEFAULT true,
        temporary_expires_at timestamptz,
        auth_version bigint NOT NULL DEFAULT 1 CHECK (auth_version > 0),
        CONSTRAINT uq_users_login UNIQUE (organization_id, login_normalized),
        CONSTRAINT ck_users_login CHECK (
            login = login_normalized AND login_normalized ~ '^[a-z0-9._-]{3,64}$'),
        CONSTRAINT ck_users_temporary CHECK (must_change_password = (temporary_expires_at IS NOT NULL)),
        CONSTRAINT ck_users_display CHECK (length(display_name) BETWEEN 1 AND 200)
    );
    CREATE TABLE task_ayuza.sessions (
        id uuid PRIMARY KEY,
        user_id uuid REFERENCES task_ayuza.users(id),
        token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
        csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
        kind varchar(12) NOT NULL CHECK (kind IN ('prelogin','password','normal')),
        created_at timestamptz NOT NULL,
        expires_at timestamptz NOT NULL,
        absolute_expires_at timestamptz NOT NULL,
        revoked_at timestamptz,
        auth_version bigint,
        CONSTRAINT ck_sessions_scope CHECK (
            (kind = 'prelogin' AND user_id IS NULL AND auth_version IS NULL) OR
            (kind <> 'prelogin' AND user_id IS NOT NULL AND auth_version IS NOT NULL AND auth_version > 0)),
        CONSTRAINT ck_sessions_expiry CHECK (created_at < expires_at AND expires_at <= absolute_expires_at)
    );
    CREATE INDEX ix_sessions_user ON task_ayuza.sessions(user_id);
    CREATE INDEX ix_sessions_expiry ON task_ayuza.sessions(absolute_expires_at);
    CREATE TABLE task_ayuza.login_attempts (
        id uuid PRIMARY KEY,
        login_key bytea NOT NULL CHECK (octet_length(login_key) = 32),
        ip_key bytea NOT NULL CHECK (octet_length(ip_key) = 32),
        attempted_at timestamptz NOT NULL
    );
    CREATE INDEX ix_attempts_login ON task_ayuza.login_attempts(login_key, attempted_at);
    CREATE INDEX ix_attempts_ip ON task_ayuza.login_attempts(ip_key, attempted_at);
    CREATE INDEX ix_attempts_time ON task_ayuza.login_attempts(attempted_at);
    CREATE TABLE task_ayuza.prelogin_limits (
        ip_key bytea PRIMARY KEY CHECK (octet_length(ip_key)=32),
        window_start timestamptz NOT NULL,
        issued_count bigint NOT NULL CHECK (issued_count BETWEEN 1 AND 30),
        updated_at timestamptz NOT NULL
    );
    CREATE INDEX ix_prelogin_limits_updated ON task_ayuza.prelogin_limits(updated_at);
    CREATE TABLE task_ayuza.auth_limit_events (
        key_kind varchar(8) NOT NULL CHECK (key_kind IN ('login','ip')),
        key_hash bytea NOT NULL CHECK (octet_length(key_hash)=32),
        last_event_at timestamptz NOT NULL,
        PRIMARY KEY(key_kind,key_hash)
    );
    CREATE INDEX ix_auth_limit_events_time ON task_ayuza.auth_limit_events(last_event_at);
    ALTER TABLE task_ayuza.audit_events DROP CONSTRAINT ck_audit_scope_m01;
    ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_scope_m01 CHECK (
        (entity_kind = 'organization' AND action IN ('organization.created','organization.updated')) OR
        (entity_kind = 'user' AND action IN ('auth.user_created','auth.password_reset','auth.password_changed','auth.deactivated','auth.login_failed','auth.login_limited','auth.login','auth.logout','auth.renewed')) OR
        (entity_kind = 'session' AND action IN ('auth.login_failed','auth.login_limited'))
    );
    ALTER TABLE task_ayuza.audit_events ADD CONSTRAINT ck_audit_auth_snapshot CHECK (
        action NOT LIKE 'auth.%' OR ("old" IS NULL AND "new" IS NULL AND workspace_id IS NULL)
    );
    """)


def downgrade():
    # Retain append-only auth audit: destructive rollback would invalidate history.
    raise RuntimeError('M01.2 downgrade is unsupported; discard only the authorized disposable cluster')
