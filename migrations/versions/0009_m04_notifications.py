"""M04.1: outbox_events, notifications

Revision ID: 0009_m04_notifications
Revises: 0008_m03_links
"""
from alembic import op

revision = "0009_m04_notifications"
down_revision = "0008_m03_links"
branch_labels = None
depends_on = None

UPGRADE_SQL = r"""
CREATE TABLE task_ayuza.outbox_events (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES task_ayuza.workspaces(id),
    task_id uuid NOT NULL REFERENCES task_ayuza.tasks(id),
    event_type varchar(24) NOT NULL,
    recipient_user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    actor_user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    source_id uuid NOT NULL,
    dedupe_key varchar(200) NOT NULL,
    state varchar(8) NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    processed_at timestamptz,
    CONSTRAINT uq_outbox_dedupe UNIQUE (dedupe_key),
    CONSTRAINT ck_outbox_type CHECK (event_type IN ('task_assigned','comment_added','blocker_resolved','dependency_changed')),
    CONSTRAINT ck_outbox_state CHECK (state IN ('pending','done','failed')),
    CONSTRAINT ck_outbox_processed CHECK ((state = 'pending') = (processed_at IS NULL)),
    CONSTRAINT ck_outbox_attempts CHECK (attempts >= 0),
    CONSTRAINT ck_outbox_not_self CHECK (recipient_user_id <> actor_user_id)
);
CREATE INDEX ix_outbox_pending ON task_ayuza.outbox_events(created_at, id) WHERE state = 'pending';

CREATE TABLE task_ayuza.notifications (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES task_ayuza.workspaces(id),
    task_id uuid NOT NULL REFERENCES task_ayuza.tasks(id),
    recipient_user_id uuid NOT NULL REFERENCES task_ayuza.users(id),
    event_type varchar(24) NOT NULL,
    outbox_event_id uuid NOT NULL REFERENCES task_ayuza.outbox_events(id),
    dedupe_key varchar(200) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    read_at timestamptz,
    CONSTRAINT uq_notifications_dedupe UNIQUE (dedupe_key),
    CONSTRAINT uq_notifications_outbox UNIQUE (outbox_event_id),
    CONSTRAINT ck_notifications_type CHECK (event_type IN ('task_assigned','comment_added','blocker_resolved','dependency_changed'))
);
CREATE INDEX ix_notifications_recipient ON task_ayuza.notifications(recipient_user_id, read_at, created_at);
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    raise RuntimeError('M04.1 downgrade is unsupported; discard only the authorized disposable cluster')
