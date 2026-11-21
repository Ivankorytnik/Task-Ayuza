"""M01.4 one-time, closed setup procedure for the first system owner and approvers (D03).

No HTTP route and no default credentials. It is run by an operator through the migrator
connection, with existing active users passed as parameters. It works once: after it
completes, setup_state is locked and the procedure refuses to run again. At least two
distinct approvers (the owner counts as one) are required, so no single person can approve
their own grant. Each person must already have MFA enabled.
"""
from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.engine import Connection


class SetupError(RuntimeError):
    pass


def complete_setup(c: Connection, owner_user_id: uuid.UUID, approver_user_ids: list) -> None:
    approvers = {uuid.UUID(str(a)) for a in approver_user_ids}
    owner = uuid.UUID(str(owner_user_id))
    if owner in approvers or not approvers:
        raise SetupError('Owner and at least one different approver are required')
    state = c.execute(text('SELECT completed_at FROM task_ayuza.setup_state FOR UPDATE')).first()
    if state is not None and state[0] is not None:
        raise SetupError('Setup is already completed')
    people = [owner, *sorted(approvers)]
    for uid in people:
        ok = c.execute(text('''SELECT 1 FROM task_ayuza.users u JOIN task_ayuza.user_mfa m ON m.user_id=u.id
            WHERE u.id=:id AND u.active AND m.enabled_at IS NOT NULL'''), {'id': uid}).first()
        if ok is None:
            raise SetupError('Every setup user must be active and have MFA enabled')
    for uid, role in [(owner, 'system_owner'), *[(a, 'access_approver') for a in sorted(approvers)]]:
        rid = uuid.uuid4()
        c.execute(text('''INSERT INTO task_ayuza.system_role_assignments
            (id, user_id, role_code, granted_by, reason, granted_at)
            VALUES (:id, :u, :r, NULL, 'initial setup', clock_timestamp())'''), {'id': rid, 'u': uid, 'r': role})
        c.execute(text('''INSERT INTO task_ayuza.audit_events (id, actor_kind, entity_kind, entity_id, action, request_id)
            VALUES (:id, 'system', 'system_role', :e, 'setup.role_assigned', :req)'''),
                  {'id': uuid.uuid4(), 'e': rid, 'req': uuid.uuid4()})
    c.execute(text('''INSERT INTO task_ayuza.setup_state (singleton, completed_at, owner_user_id)
        VALUES (true, clock_timestamp(), :o)
        ON CONFLICT (singleton) DO UPDATE SET completed_at=EXCLUDED.completed_at, owner_user_id=EXCLUDED.owner_user_id'''),
              {'o': owner})
    c.execute(text('''INSERT INTO task_ayuza.audit_events (id, actor_kind, entity_kind, entity_id, action, request_id)
        VALUES (:id, 'system', 'setup', :e, 'setup.completed', :req)'''),
              {'id': uuid.uuid4(), 'e': owner, 'req': uuid.uuid4()})
