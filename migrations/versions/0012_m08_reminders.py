"""M08.1: system reminders. Outbox events may have no actor (a system reminder); two new event types.

Revision ID: 0012_m08_reminders
Revises: 0011_m04_exports
"""
from alembic import op

revision = "0012_m08_reminders"
down_revision = "0011_m04_exports"
branch_labels = None
depends_on = None

TYPES = "'task_assigned','comment_added','blocker_resolved','dependency_changed','task_due_soon','task_overdue'"

UPGRADE_SQL = f"""
ALTER TABLE task_ayuza.outbox_events ALTER COLUMN actor_user_id DROP NOT NULL;
ALTER TABLE task_ayuza.outbox_events DROP CONSTRAINT ck_outbox_not_self;
ALTER TABLE task_ayuza.outbox_events ADD CONSTRAINT ck_outbox_not_self
    CHECK (actor_user_id IS NULL OR recipient_user_id <> actor_user_id);
ALTER TABLE task_ayuza.outbox_events DROP CONSTRAINT ck_outbox_type;
ALTER TABLE task_ayuza.outbox_events ADD CONSTRAINT ck_outbox_type CHECK (event_type IN ({TYPES}));
ALTER TABLE task_ayuza.notifications DROP CONSTRAINT ck_notifications_type;
ALTER TABLE task_ayuza.notifications ADD CONSTRAINT ck_notifications_type CHECK (event_type IN ({TYPES}));
"""


def upgrade():
    op.execute(UPGRADE_SQL)


def downgrade():
    raise RuntimeError('M08.1 downgrade is unsupported; discard only the authorized disposable cluster')
