"""M04.2 tests: risk center. Disposable PostgreSQL, synthetic data only."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from backend.risks import RisksService, severity_of
from test_m01_acl import acl, admin_sql, mark_mfa, migrator, person, rows, status, violates, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join, new_task  # noqa: F401

SECRET = 'Synthetic confidential risk text'


@pytest.fixture(scope='module')
def risks(service):
    return RisksService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def controller(service, migrator, mfa=True):
    who = person(service)
    admin_sql(migrator, '''INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason)
        VALUES (:id, :u, 'risk_controller', 'synthetic')''', id=uuid.uuid4(), u=who.id)
    if mfa:
        mark_mfa(migrator, who)
    return who


def future(days=30):
    return datetime.now(timezone.utc) + timedelta(days=days)


def new_risk(risks, who, **kw):
    kw.setdefault('category', 'backup')
    kw.setdefault('description', SECRET)
    kw.setdefault('probability', 3)
    kw.setdefault('impact', 3)
    kw.setdefault('owner_user_id', who.id)
    return risks.create_risk(who.token, who.csrf, **kw)


def test_i01_access_validation_and_versions(service, risks, w, migrator):
    plain = person(service)
    c = controller(service, migrator, mfa=False)
    assert status(lambda: new_risk(risks, plain)) == 404                        # the area is hidden
    assert status(lambda: new_risk(risks, c)) == 403                            # a write needs a fresh MFA
    mark_mfa(migrator, c)
    assert status(lambda: new_risk(risks, c, category='nope')) == 422
    assert status(lambda: new_risk(risks, c, probability=0)) == 422
    assert status(lambda: new_risk(risks, c, impact=True)) == 422
    assert status(lambda: new_risk(risks, c, owner_user_id=None)) == 422
    assert status(lambda: new_risk(risks, c, owner_user_id=uuid.uuid4())) == 422
    r = new_risk(risks, c, probability=5, impact=5)
    assert r['control_status'] == 'gray'
    assert risks.get_risk(c.token, r['id'])['severity'] == 'critical'
    assert [severity_of(1, 4), severity_of(3, 3), severity_of(4, 4), severity_of(5, 4)] == ['low', 'medium', 'high', 'critical']
    assert status(lambda: risks.get_risk(plain.token, r['id'])) == 404
    assert status(lambda: risks.list_risks(plain.token)) == 404
    assert risks.get_risk(w.sysadmin.token, r['id'])['id'] == r['id']          # system administrator may read
    assert status(lambda: risks.update_risk(c.token, c.csrf, r['id'], 1, {'status': 'x'})) == 422
    upd = risks.update_risk(c.token, c.csrf, r['id'], 1, {'probability': 1, 'impact': 2})
    assert upd['version'] == 2 and risks.get_risk(c.token, r['id'])['severity'] == 'low'
    assert risks.update_risk(c.token, c.csrf, r['id'], 2, {'probability': 1})['changed'] is False
    assert status(lambda: risks.update_risk(c.token, c.csrf, r['id'], 1, {'measures': 'x'})) == 409
    assert status(lambda: risks.update_risk(c.token, c.csrf, r['id'], 2, {'owner_user_id': None})) == 422
    arch = risks.set_risk_archived(c.token, c.csrf, r['id'], True, 2)
    assert status(lambda: risks.update_risk(c.token, c.csrf, r['id'], arch['version'], {'measures': 'x'})) == 409
    assert r['id'] not in [x['id'] for x in risks.list_risks(c.token)]
    assert r['id'] in [x['id'] for x in risks.list_risks(c.token, include_archived=True)]
    risks.set_risk_archived(c.token, c.csrf, r['id'], False, arch['version'])
    dump = repr(rows(migrator, 'SELECT * FROM task_ayuza.audit_events WHERE entity_kind=\'risk\''))
    assert SECRET not in dump and 'risk.created' in dump and 'risk.updated' in dump


def test_i02_traffic_light_never_defaults_to_green(service, risks, w, migrator):
    c = controller(service, migrator)
    r = new_risk(risks, c)['id']
    assert risks.get_risk(c.token, r)['control_status'] == 'gray'
    assert status(lambda: risks.record_check(c.token, c.csrf, r, 'pass')) == 422
    assert status(lambda: risks.record_check(c.token, c.csrf, r, 'pass', 'doc-1', datetime.now(timezone.utc) - timedelta(days=1))) == 422
    assert status(lambda: risks.record_check(c.token, c.csrf, r, 'maybe')) == 422
    assert risks.get_risk(c.token, r)['control_status'] == 'gray'
    assert risks.record_check(c.token, c.csrf, r, 'fail', 'ticket-7')['control_status'] == 'yellow'
    assert risks.record_check(c.token, c.csrf, r, 'critical')['control_status'] == 'red'
    ok = risks.record_check(c.token, c.csrf, r, 'pass', 'evidence-9', future())
    assert ok['control_status'] == 'green' and risks.get_risk(c.token, r)['control_status'] == 'green'
    assert r in [x['id'] for x in risks.list_risks(c.token, control_status='green')]
    admin_sql(migrator, "UPDATE task_ayuza.risk_checks SET checked_at = now() - interval '2 hours', valid_until = now() - interval '1 hour' WHERE id=:id", id=ok['id'])
    assert risks.get_risk(c.token, r)['control_status'] == 'yellow'              # expired confirmation
    assert [x['result'] for x in risks.list_checks(c.token, r)] == ['fail', 'critical', 'pass']
    # automatic checks never prove legal or personal data compliance
    legal = new_risk(risks, c, category='legal')['id']
    assert risks.record_system_check(legal, 'backup.age', 'pass', 'auto-1', future())['control_status'] == 'yellow'
    tech = new_risk(risks, c, category='backup')['id']
    assert risks.record_system_check(tech, 'backup.age', 'pass', 'auto-2', future())['control_status'] == 'green'
    assert rows(migrator, 'SELECT system_check_code, checker_user_id FROM task_ayuza.risk_checks WHERE risk_id=:r', r=tech) == [
        {'system_check_code': 'backup.age', 'checker_user_id': None}]
    # database rules behind the service
    violates(migrator, "UPDATE task_ayuza.risk_register SET control_status='green', last_check_id=NULL WHERE id=:id", '23514', id=legal)
    violates(migrator, "INSERT INTO task_ayuza.risk_checks (id, risk_id, result, severity) VALUES (gen_random_uuid(), :r, 'fail', 'low')", '23514', r=r)
    violates(migrator, "INSERT INTO task_ayuza.risk_checks (id, risk_id, checker_user_id, system_check_code, result, severity) VALUES (gen_random_uuid(), :r, :u, 'sys.check', 'fail', 'low')", '23514', r=r, u=c.id)
    violates(migrator, "INSERT INTO task_ayuza.risk_checks (id, risk_id, checker_user_id, result, severity) VALUES (gen_random_uuid(), :r, :u, 'pass', 'low')", '23514', r=r, u=c.id)


def test_i03_links_are_read_by_each_sides_own_rights(service, acl, risks, w, migrator):
    c1, c2 = controller(service, migrator), controller(service, migrator)
    a = join(acl, w, person(service))
    join(acl, w, c1, team=False)
    t = new_task(risks, a, w)['id']
    r = new_risk(risks, c1)['id']
    assert status(lambda: risks.set_risk_task_link(c1.token, c1.csrf, r, t, True)) == 404   # a risk does not open the task
    grant = risks.set_task_access(a.token, a.csrf, t, c1.id, 'read', True, 'review')
    link = risks.set_risk_task_link(c1.token, c1.csrf, r, t, True)
    assert link['changed'] is True and risks.set_risk_task_link(c1.token, c1.csrf, r, t, True)['changed'] is False
    seen = risks.list_risk_links(c1.token, r)
    assert [x['task_id'] for x in seen['tasks']] == [t] and seen['hidden_tasks'] == 0
    other = risks.list_risk_links(c2.token, r)                                               # another controller, no task access
    assert other['tasks'] == [] and other['hidden_tasks'] == 1 and SECRET not in repr(other) and str(t) not in repr(other)
    assert status(lambda: risks.get_risk(a.token, r)) == 404                                 # the task owner gets no risk access
    # a blocker is linked by the rights to its blocked task
    b = risks.create_blocker(a.token, a.csrf, t, 'Synthetic blocker', responsible_user_id=a.id)['id']
    assert risks.set_risk_blocker_link(c1.token, c1.csrf, r, b, True)['changed'] is True
    assert [x['blocker_id'] for x in risks.list_risk_links(c1.token, r)['blockers']] == [b]
    assert risks.list_risk_links(c2.token, r)['hidden_blockers'] == 1
    # access withdrawn: the next read hides both sides
    risks.set_task_access(a.token, a.csrf, t, c1.id, 'read', False, 'done', expected_version=grant['version'])
    gone = risks.list_risk_links(c1.token, r)
    assert gone['tasks'] == [] and gone['blockers'] == [] and gone['hidden_tasks'] == 1 and gone['hidden_blockers'] == 1
    violates(migrator, "INSERT INTO task_ayuza.risk_task_links (id, risk_id, task_id, created_by) VALUES (gen_random_uuid(), :r, :t, :u)", '23505', r=r, t=t, u=c1.id)
    violates(migrator, "INSERT INTO task_ayuza.risk_blocker_links (id, risk_id, blocker_id, created_by) VALUES (gen_random_uuid(), :r, :b, :u)", '23505', r=r, b=b, u=c1.id)


def test_i04_privileges(service, risks, w, migrator):
    runtime = service.engine
    for table in ('risk_register', 'risk_checks', 'risk_task_links', 'risk_blocker_links'):
        violates(runtime, f'TRUNCATE task_ayuza.{table}', '42501')
        violates(runtime, f'DELETE FROM task_ayuza.{table} WHERE false', '42501')
    violates(runtime, "UPDATE task_ayuza.risk_checks SET result='pass' WHERE false", '42501')
