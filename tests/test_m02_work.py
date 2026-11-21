"""M02.1 tests: projects, project members, tasks, object rights (D01/D02), D04 statuses, audit.

Disposable loopback PostgreSQL only, synthetic data only (run by tests/run_m01_acceptance.py).
"""
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from backend.acl import AclError, AclService
from backend.work import WorkService
from test_m01_acl import (acl, admin_sql, make_workspace_admin, mark_mfa, migrator, person, rows, status, violates,  # noqa: F401
                          world)
from test_m01_auth import service  # noqa: F401

TITLE = 'Synthetic confidential title'


@pytest.fixture(scope='module')
def work(service):
    return WorkService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def join(acl, w, who, role='participant', team=True):
    acl.set_workspace_member(w.admin.token, w.admin.csrf, w.ws, who.id, role)
    if team:
        acl.set_team_member(w.sysadmin.token, w.sysadmin.csrf, w.team, who.id)
    return who


def new_project(work, who, w, owner=None, **kw):
    return work.create_project(who.token, who.csrf, w.ws, TITLE, 'desc', (owner or who).id, **kw)


def new_task(work, who, w, owner=None, **kw):
    kw.setdefault('title', TITLE)
    return work.create_task(who.token, who.csrf, w.ws, result_owner_user_id=(owner or who).id,
                            executor_team_id=w.team, **kw)


def grant(migrator, who, ws, capability, approver, minutes=60):
    admin_sql(migrator, '''INSERT INTO task_ayuza.administrative_grants
        (id, grantee_user_id, workspace_id, capability, kind, approver_user_id, reason, valid_from, expires_at)
        VALUES (gen_random_uuid(), :g, :w, :cap, 'emergency', :by, 'synthetic', clock_timestamp(),
                clock_timestamp() + CAST(:term AS interval))''',
              g=who.id, w=ws, cap=capability, by=approver.id, term=f'{minutes} minutes')
    mark_mfa(migrator, who)


def test_c01_project_creation_rights(service, acl, work, w, migrator):
    p = new_project(work, w.member, w)
    assert p['version'] == 1
    assert status(lambda: new_project(work, w.admin, w)) == 403        # no administrator bypass
    assert status(lambda: new_project(work, w.outsider, w)) == 404
    observer = join(acl, w, person(service), 'observer', team=False)
    assert status(lambda: new_project(work, observer, w)) == 403
    assert status(lambda: work.create_project(w.member.token, w.member.csrf, w.ws, TITLE, '', w.outsider.id)) == 422
    assert status(lambda: work.create_project(w.member.token, w.member.csrf, w.ws, '  ', '', w.member.id)) == 422
    assert status(lambda: work.create_project(w.member.token, w.member.csrf, w.ws, 'T', '', w.member.id,
                                              start_date='2026-12-02', due_date='2026-12-01')) == 422
    members = rows(migrator, 'SELECT role FROM task_ayuza.project_members WHERE project_id=:p', p=p['id'])
    assert [m['role'] for m in members] == ['project_manager']
    granted = person(service)
    make_workspace_admin(migrator, w.ws, granted)
    assert status(lambda: work.create_project(granted.token, granted.csrf, w.ws, 'Granted', '', w.member.id)) == 403
    grant(migrator, granted, w.ws, 'content_edit', w.sysadmin)
    assert work.create_project(granted.token, granted.csrf, w.ws, 'Granted', '', w.member.id)['version'] == 1


def test_c02_project_visibility_members_and_versions(service, acl, work, w, migrator):
    owner = join(acl, w, person(service))
    other = join(acl, w, person(service))
    watcher = join(acl, w, person(service))
    p = new_project(work, owner, w)
    pid = p['id']
    assert work.get_project(owner.token, pid)['id'] == pid
    assert status(lambda: work.get_project(other.token, pid)) == 404
    assert status(lambda: work.get_project(w.admin.token, pid)) == 404
    assert work.list_projects(other.token, w.ws) == [] or all(r['id'] != pid for r in work.list_projects(other.token, w.ws))
    added = work.set_project_member(owner.token, owner.csrf, pid, other.id, 'participant', True)
    assert added['created'] is True
    assert work.set_project_member(owner.token, owner.csrf, pid, other.id, 'participant', True)['created'] is False
    work.set_project_member(owner.token, owner.csrf, pid, watcher.id, 'observer', True)
    assert work.get_project(other.token, pid)['id'] == pid and work.get_project(watcher.token, pid)['id'] == pid
    assert status(lambda: work.set_project_member(other.token, other.csrf, pid, watcher.id, 'participant', True)) == 403
    assert status(lambda: work.set_project_member(owner.token, owner.csrf, pid, owner.id, 'observer', True)) == 403
    assert status(lambda: work.set_project_member(owner.token, owner.csrf, pid, w.outsider.id, 'participant', True)) == 422
    assert status(lambda: work.set_project_member(owner.token, owner.csrf, pid, other.id, 'observer', True, 99)) == 409
    work.set_project_member(owner.token, owner.csrf, pid, other.id, 'participant', False, added['version'])
    assert status(lambda: work.get_project(other.token, pid)) == 404   # deactivated at once
    # updates: manager only, optimistic version, idempotent, archive blocks changes
    assert status(lambda: work.update_project(watcher.token, watcher.csrf, pid, 1, {'title': 'x'})) == 403
    upd = work.update_project(owner.token, owner.csrf, pid, 1, {'title': 'Renamed'})
    assert upd['version'] == 2 and upd['changed'] is True
    assert work.update_project(owner.token, owner.csrf, pid, 1, {'title': 'Renamed'})['changed'] is False
    assert status(lambda: work.update_project(owner.token, owner.csrf, pid, 1, {'title': 'Again'})) == 409
    assert status(lambda: work.update_project(owner.token, owner.csrf, pid, 2, {'status': 'x'})) == 422
    arch = work.set_project_archived(owner.token, owner.csrf, pid, True, 2)
    assert work.set_project_archived(owner.token, owner.csrf, pid, True, 2)['changed'] is False
    assert status(lambda: work.update_project(owner.token, owner.csrf, pid, arch['version'], {'title': 'Z'})) == 409
    assert status(lambda: new_task(work, owner, w, project_id=pid)) == 409
    work.set_project_archived(owner.token, owner.csrf, pid, False, arch['version'])


def test_c03_task_creation_rules(service, acl, work, w, migrator):
    t = new_task(work, w.member, w)
    assert t['version'] == 1
    assert status(lambda: new_task(work, w.admin, w)) == 403
    assert status(lambda: new_task(work, w.outsider, w)) == 404
    other = join(acl, w, person(service))
    assert status(lambda: new_task(work, w.member, w, owner=other)) == 403            # naming another owner is assignment
    foreign = acl.create_team(w.sysadmin.token, w.sysadmin.csrf, 'Synthetic Foreign')['id']
    assert status(lambda: work.create_task(w.member.token, w.member.csrf, w.ws, TITLE, w.member.id, foreign)) == 422
    lone = join(acl, w, person(service), team=False)
    assert status(lambda: new_task(work, w.member, w, assignee_user_id=lone.id)) == 422  # not in executor team
    assert new_task(work, w.member, w, assignee_user_id=other.id)['version'] == 1
    assert status(lambda: new_task(work, w.member, w, priority='urgent')) == 422
    assert status(lambda: new_task(work, w.member, w, title='')) == 422
    assert status(lambda: new_task(work, w.member, w, project_id=uuid.uuid4())) == 404
    assert status(lambda: new_task(work, w.member, w, start_date='2026-12-05', due_date='2026-12-01')) == 422
    observer = join(acl, w, person(service), 'observer', team=False)
    assert status(lambda: new_task(work, observer, w)) == 403


def test_c04_read_basis_no_bypass_and_pagination(service, acl, work, w, migrator):
    author = join(acl, w, person(service))
    ally = join(acl, w, person(service))
    stranger = join(acl, w, person(service), team=False)
    t = new_task(work, author, w, assignee_user_id=ally.id)
    assert work.get_task(author.token, t['id'])['id'] == t['id']
    assert work.get_task(ally.token, t['id'])['id'] == t['id']
    assert work.get_task(w.member.token, t['id'])['id'] == t['id']      # executor team member
    assert status(lambda: work.get_task(stranger.token, t['id'])) == 404  # same workspace, no basis
    assert status(lambda: work.get_task(w.admin.token, t['id'])) == 404   # administrator: no bypass
    assert status(lambda: work.get_task(w.outsider.token, t['id'])) == 404
    assert status(lambda: work.get_task(stranger.token, uuid.uuid4())) == 404
    for _ in range(2):
        new_task(work, author, w)
    first = work.list_tasks(author.token, w.ws, limit=2)
    second = work.list_tasks(author.token, w.ws, limit=200, after=first[-1]['id'])
    ids = [r['id'] for r in first] + [r['id'] for r in second]
    assert len(first) == 2 and ids == sorted(ids) and len(ids) == len(set(ids))
    assert work.list_tasks(stranger.token, w.ws) == []
    assert status(lambda: work.list_tasks(w.outsider.token, w.ws)) == 404
    assert status(lambda: work.list_tasks(author.token, w.ws, limit=0)) == 422


def test_c05_project_tasks_and_hidden_project(service, acl, work, w, migrator):
    pm = join(acl, w, person(service))
    member = join(acl, w, person(service))
    observer = join(acl, w, person(service))
    assigned = join(acl, w, person(service), team=False)
    bystander = join(acl, w, person(service), team=False)
    pid = new_project(work, pm, w)['id']
    work.set_project_member(pm.token, pm.csrf, pid, member.id, 'participant', True)
    work.set_project_member(pm.token, pm.csrf, pid, observer.id, 'observer', True)
    assert status(lambda: new_task(work, bystander, w, project_id=pid)) == 404
    assert status(lambda: new_task(work, observer, w, project_id=pid)) == 403
    t = new_task(work, member, w, project_id=pid)
    tid = t['id']
    assert work.get_task(observer.token, tid)['id'] == tid
    assert status(lambda: work.update_task(observer.token, observer.csrf, tid, 1, {'title': 'x'})) == 403
    assert work.update_task(member.token, member.csrf, tid, 1, {'priority': 'high'})['version'] == 2
    pm_task = new_task(work, pm, w, project_id=pid, owner=member)       # manager names an owner: assignment
    assert pm_task['version'] == 1
    # project task assigned to someone with no project role: task visible, project details hidden
    sub = join(acl, w, person(service))
    work.assign_task(pm.token, pm.csrf, tid, 2, assignee_user_id=sub.id)
    assert work.get_task(sub.token, tid)['project_id'] == pid
    assert status(lambda: work.get_project(sub.token, pid)) == 404
    assert status(lambda: work.update_task(bystander.token, bystander.csrf, tid, 3, {'title': 'x'})) == 404
    assert work.list_tasks(bystander.token, w.ws) == []


def test_c06_status_rules_d04_and_audit_content(service, acl, work, w, migrator):
    a = join(acl, w, person(service))
    t = new_task(work, a, w)['id']
    v = work.update_task(a.token, a.csrf, t, 1, {'status': 'in_progress'})['version']
    done = work.update_task(a.token, a.csrf, t, v, {'status': 'done'})
    row = rows(migrator, 'SELECT status, closed_at FROM task_ayuza.tasks WHERE id=:id', id=t)[0]
    assert row['status'] == 'done' and row['closed_at'] is not None
    assert status(lambda: work.update_task(a.token, a.csrf, t, done['version'], {'status': 'cancelled'})) == 422
    assert status(lambda: work.update_task(a.token, a.csrf, t, done['version'], {'status': 'unknown'})) == 422
    reopened = work.update_task(a.token, a.csrf, t, done['version'], {'status': 'in_progress'})
    assert rows(migrator, 'SELECT closed_at FROM task_ayuza.tasks WHERE id=:id', id=t)[0]['closed_at'] is None
    cancelled = work.update_task(a.token, a.csrf, t, reopened['version'], {'status': 'cancelled'})
    assert status(lambda: work.update_task(a.token, a.csrf, t, cancelled['version'], {'status': 'done'})) == 422
    assert work.update_task(a.token, a.csrf, t, cancelled['version'], {'status': 'cancelled'})['changed'] is False
    assert status(lambda: work.update_task(a.token, a.csrf, t, 1, {'title': 'late'})) == 409
    actions = [r['action'] for r in rows(migrator, 'SELECT action FROM task_ayuza.audit_events WHERE entity_id=:id ORDER BY occurred_at', id=t)]
    assert actions.count('task.status_changed') == 4 and 'task.created' in actions
    t2 = new_task(work, a, w)['id']
    work.update_task(a.token, a.csrf, t2, 1, {'title': 'Another confidential', 'description': 'secret text'})
    dump = repr(rows(migrator, 'SELECT "old","new" FROM task_ayuza.audit_events'))
    assert 'confidential' not in dump and 'secret text' not in dump and TITLE not in dump


def test_c07_assignment_and_archive_rights(service, acl, work, w, migrator):
    owner = join(acl, w, person(service))
    author = join(acl, w, person(service))
    helper = join(acl, w, person(service))
    lone = join(acl, w, person(service), team=False)
    t = work.create_task(author.token, author.csrf, w.ws, TITLE, author.id, w.team)['id']
    # the author is also the result owner here, so reassign ownership to someone else
    first = work.assign_task(author.token, author.csrf, t, 1, result_owner_user_id=owner.id)
    assert first['version'] == 2
    assert status(lambda: work.assign_task(author.token, author.csrf, t, 2, assignee_user_id=helper.id)) == 403
    assert status(lambda: work.set_task_archived(author.token, author.csrf, t, True, 2)) == 403
    assert work.update_task(author.token, author.csrf, t, 2, {'priority': 'low'})['version'] == 3  # edit stays allowed
    assert status(lambda: work.assign_task(owner.token, owner.csrf, t, 3, assignee_user_id=lone.id)) == 422
    assert work.assign_task(owner.token, owner.csrf, t, 3, assignee_user_id=helper.id)['version'] == 4
    assert work.assign_task(owner.token, owner.csrf, t, 4, assignee_user_id=helper.id)['changed'] is False
    other_team = acl.create_team(w.sysadmin.token, w.sysadmin.csrf, 'Synthetic Other Team')['id']
    assert status(lambda: work.assign_task(owner.token, owner.csrf, t, 4, executor_team_id=other_team)) == 422
    assert status(lambda: work.assign_task(owner.token, owner.csrf, t, 4, result_owner_user_id=w.outsider.id)) == 422
    assert status(lambda: work.assign_task(owner.token, owner.csrf, t, 1, assignee_user_id=None)) == 409
    assert status(lambda: work.assign_task(helper.token, helper.csrf, t, 4, assignee_user_id=None)) == 403
    archived = work.set_task_archived(owner.token, owner.csrf, t, True, 4)
    assert status(lambda: work.update_task(owner.token, owner.csrf, t, archived['version'], {'title': 'x'})) == 409
    assert all(r['id'] != t for r in work.list_tasks(owner.token, w.ws, limit=200))
    work.set_task_archived(owner.token, owner.csrf, t, False, archived['version'])
    assert any(r['id'] == t for r in work.list_tasks(owner.token, w.ws, limit=200))
    actions = {r['action'] for r in rows(migrator, 'SELECT action FROM task_ayuza.audit_events WHERE entity_id=:id', id=t)}
    assert {'task.assigned', 'task.archived', 'task.restored'} <= actions


def test_c08_grants_open_content_only_with_mfa(service, acl, work, w, migrator):
    author = join(acl, w, person(service))
    t = new_task(work, author, w)['id']
    auditor = person(service)
    join(acl, w, auditor, 'observer', team=False)
    assert status(lambda: work.get_task(auditor.token, t)) == 404
    grant(migrator, auditor, w.ws, 'read', w.sysadmin)
    assert work.get_task(auditor.token, t)['id'] == t
    assert any(r['id'] == t for r in work.list_tasks(auditor.token, w.ws, limit=200))
    assert status(lambda: work.update_task(auditor.token, auditor.csrf, t, 1, {'title': 'x'})) == 403
    admin_sql(migrator, 'UPDATE task_ayuza.sessions SET mfa_verified_at = NULL WHERE user_id=:u', u=auditor.id)
    assert status(lambda: work.get_task(auditor.token, t)) == 403          # stale MFA
    editor = person(service)
    join(acl, w, editor, 'participant', team=False)
    grant(migrator, editor, w.ws, 'content_edit', w.sysadmin)
    assert work.update_task(editor.token, editor.csrf, t, 1, {'priority': 'critical'})['version'] == 2
    admin_sql(migrator, "UPDATE task_ayuza.administrative_grants SET valid_from = valid_from - interval '50 minutes', expires_at = clock_timestamp() - interval '1 minute' WHERE grantee_user_id=:u", u=editor.id)
    assert status(lambda: work.update_task(editor.token, editor.csrf, t, 2, {'priority': 'low'})) == 404


def test_c09_postgres_constraints(service, acl, work, w, migrator):
    author = join(acl, w, person(service))
    t = new_task(work, author, w)['id']
    pid = new_project(work, author, w)['id']
    for table in ('projects', 'project_members', 'tasks'):
        violates(service.engine, f'TRUNCATE task_ayuza.{table}', '42501')
        violates(service.engine, f'DELETE FROM task_ayuza.{table} WHERE false', '42501')
    violates(migrator, "UPDATE task_ayuza.tasks SET status='archived' WHERE id=:id", '23514', id=t)
    violates(migrator, "UPDATE task_ayuza.tasks SET status='done' WHERE id=:id", '23514', id=t)          # done needs closed_at
    violates(migrator, "UPDATE task_ayuza.tasks SET closed_at=now() WHERE id=:id", '23514', id=t)        # closed_at only for done
    violates(migrator, "UPDATE task_ayuza.tasks SET priority='urgent' WHERE id=:id", '23514', id=t)
    violates(migrator, "UPDATE task_ayuza.tasks SET title='  ' WHERE id=:id", '23514', id=t)
    violates(migrator, "UPDATE task_ayuza.tasks SET version=0 WHERE id=:id", '23514', id=t)
    violates(migrator, "UPDATE task_ayuza.tasks SET assignee_user_id=:u WHERE id=:id", '23503', id=t, u=w.outsider.id)
    violates(migrator, "UPDATE task_ayuza.tasks SET executor_team_id=gen_random_uuid() WHERE id=:id", '23503', id=t)
    ws2 = admin_ws(migrator)
    violates(migrator, "UPDATE task_ayuza.tasks SET workspace_id=:w WHERE id=:id", '23503', id=t, w=ws2)
    violates(migrator, "UPDATE task_ayuza.projects SET title='' WHERE id=:id", '23514', id=pid)
    violates(migrator, "UPDATE task_ayuza.projects SET start_date='2026-12-02', due_date='2026-12-01' WHERE id=:id", '23514', id=pid)
    violates(migrator, "UPDATE task_ayuza.project_members SET role='boss' WHERE project_id=:id", '23514', id=pid)
    audit_insert = '''INSERT INTO task_ayuza.audit_events
        (id, actor_kind, actor_id, session_id, workspace_id, entity_kind, entity_id, action, request_id, "new")
        SELECT gen_random_uuid(), 'user', :u, s.id, :w, 'task', gen_random_uuid(), :action, gen_random_uuid(),
               CAST(:new AS jsonb) FROM task_ayuza.sessions s WHERE s.user_id=:u LIMIT 1'''
    violates(migrator, audit_insert, '23514', u=author.id, w=w.ws, action='task.created', new='{"title":"leak"}')
    violates(migrator, audit_insert, '23514', u=author.id, w=w.ws, action='task.deleted', new='{"status":"new"}')
    violates(migrator, audit_insert, '23514', u=author.id, w=w.ws, action='task.updated', new='{"status":"weird"}')


def admin_ws(migrator):
    wid = uuid.uuid4()
    admin_sql(migrator, '''INSERT INTO task_ayuza.workspaces (id, organization_id, name, timezone)
        SELECT :id, id, 'Synthetic Second', 'UTC' FROM task_ayuza.organization LIMIT 1''', id=wid)
    return wid


def test_c10_concurrent_update_has_one_winner(service, acl, work, w, migrator):
    author = join(acl, w, person(service))
    t = new_task(work, author, w)['id']

    def attempt(priority):
        try:
            return work.update_task(author.token, author.csrf, t, 1, {'priority': priority})['version']
        except AclError as error:
            return error.status
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(attempt, ['low', 'high', 'critical', 'low']))
    assert sorted(r for r in results if r == 2) == [2] or results.count(2) >= 1
    assert results.count(409) + results.count(2) == 4
    row = rows(migrator, 'SELECT version FROM task_ayuza.tasks WHERE id=:id', id=t)[0]
    assert row['version'] == 2
