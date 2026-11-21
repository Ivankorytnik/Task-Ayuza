"""M02.2 tests: labels, stages, subtasks, checklists, comments. Disposable PostgreSQL, synthetic data only."""
import uuid

import pytest

from backend.acl import AclError
from backend.work_items import ItemsService
from test_m01_acl import (acl, admin_sql, mark_mfa, migrator, person, rows, status, violates,  # noqa: F401
                          world)
from test_m01_auth import service  # noqa: F401
from test_m02_work import admin_ws, grant, join, new_project, new_task, TITLE  # noqa: F401


@pytest.fixture(scope='module')
def items(service):
    return ItemsService(service)


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


def test_d01_labels(service, acl, items, w, migrator):
    a = join(acl, w, person(service))
    obs = join(acl, w, person(service), 'observer', team=False)
    first = items.create_label(a.token, a.csrf, w.ws, 'Urgent')
    assert first['created'] is True
    assert items.create_label(a.token, a.csrf, w.ws, 'urgent')['created'] is False      # unique ignoring case
    assert status(lambda: items.create_label(obs.token, obs.csrf, w.ws, 'X')) == 403
    assert status(lambda: items.create_label(w.outsider.token, w.outsider.csrf, w.ws, 'X')) == 404
    assert status(lambda: items.create_label(a.token, a.csrf, w.ws, '  ')) == 422
    assert [l['name'] for l in items.list_labels(a.token, w.ws)].count('Urgent') == 1
    assert status(lambda: items.list_labels(w.outsider.token, w.ws)) == 404
    p = new_project(items, a, w)['id']
    t = new_task(items, a, w)['id']
    assert items.set_project_label(a.token, a.csrf, p, first['id'])['changed'] is True
    assert items.set_project_label(a.token, a.csrf, p, first['id'])['changed'] is False
    assert items.set_task_label(a.token, a.csrf, t, first['id'])['changed'] is True
    assert [l['id'] for l in items.list_task_labels(a.token, t)] == [first['id']]
    assert items.set_task_label(a.token, a.csrf, t, first['id'], False)['changed'] is True
    assert items.list_task_labels(a.token, t) == []
    # a label from another workspace cannot be attached
    ws2 = uuid.uuid4()
    foreign_ws = admin_ws(migrator)
    admin_sql(migrator, "INSERT INTO task_ayuza.labels (id, workspace_id, name) VALUES (:id, :w, 'Foreign')", id=ws2, w=foreign_ws)
    assert status(lambda: items.set_task_label(a.token, a.csrf, t, ws2)) == 422
    assert status(lambda: items.set_task_label(w.outsider.token, w.outsider.csrf, t, first['id'])) == 404
    assert status(lambda: items.set_project_label(obs.token, obs.csrf, p, first['id'])) == 404


def test_d02_stages_and_task_stage(service, acl, items, w, migrator):
    pm = join(acl, w, person(service))
    member = join(acl, w, person(service))
    pid = new_project(items, pm, w)['id']
    items.set_project_member(pm.token, pm.csrf, pid, member.id, 'participant', True)
    st = items.create_stage(pm.token, pm.csrf, pid, 'Phase 1', '2026-12-01', '2026-12-31', 1)
    assert status(lambda: items.create_stage(member.token, member.csrf, pid, 'No', None, None)) == 403
    assert status(lambda: items.create_stage(pm.token, pm.csrf, pid, 'Bad', '2026-12-05', '2026-12-01')) == 422
    upd = items.update_stage(pm.token, pm.csrf, st['id'], 1, {'title': 'Phase 1b'})
    assert upd['version'] == 2
    assert status(lambda: items.update_stage(pm.token, pm.csrf, st['id'], 1, {'title': 'Old'})) == 409
    assert [x['id'] for x in items.list_stages(member.token, pid)] == [st['id']]
    t = new_task(items, member, w, project_id=pid)['id']
    assert items.set_task_stage(member.token, member.csrf, t, st['id'], 1)['version'] == 2
    assert items.set_task_stage(member.token, member.csrf, t, st['id'], 2)['changed'] is False
    standalone = new_task(items, member, w)['id']
    assert status(lambda: items.set_task_stage(member.token, member.csrf, standalone, st['id'], 1)) == 422
    other_pid = new_project(items, pm, w)['id']
    other_stage = items.create_stage(pm.token, pm.csrf, other_pid, 'Elsewhere')['id']
    assert status(lambda: items.set_task_stage(member.token, member.csrf, t, other_stage, 2)) == 422
    archived = items.set_stage_archived(pm.token, pm.csrf, st['id'], True, 2)
    assert status(lambda: items.set_task_stage(member.token, member.csrf, t, st['id'], 2)) == 409
    assert items.list_stages(pm.token, pid) == []
    items.set_stage_archived(pm.token, pm.csrf, st['id'], False, archived['version'])
    violates(migrator, "UPDATE task_ayuza.tasks SET stage_id=:s WHERE id=:id", '23514', id=standalone, s=st['id'])


def test_d03_subtasks(service, acl, items, w, migrator):
    a = join(acl, w, person(service))
    stranger = join(acl, w, person(service), team=False)
    parent = new_task(items, a, w)['id']
    child = new_task(items, a, w, parent_task_id=parent)
    assert child['version'] == 1
    assert rows(migrator, 'SELECT parent_task_id FROM task_ayuza.tasks WHERE id=:id', id=child['id'])[0]['parent_task_id'] == parent
    assert status(lambda: new_task(items, a, w, parent_task_id=child['id'])) == 422      # one level only
    assert status(lambda: new_task(items, stranger, w, parent_task_id=parent)) == 404     # parent hidden
    pid = new_project(items, a, w)['id']
    assert status(lambda: new_task(items, a, w, parent_task_id=parent, project_id=pid)) == 422  # project mismatch
    assert status(lambda: new_task(items, a, w, parent_task_id=uuid.uuid4())) == 404
    # database guards: self parent, cycle, project change under a parent
    violates(migrator, "UPDATE task_ayuza.tasks SET parent_task_id=id WHERE id=:id", '23514', id=parent)
    violates(migrator, "UPDATE task_ayuza.tasks SET parent_task_id=:ch WHERE id=:p", '23514', p=parent, ch=child['id'])
    violates(migrator, "UPDATE task_ayuza.tasks SET project_id=:pr WHERE id=:p", '23514', p=parent, pr=pid)
    audit_new = rows(migrator, "SELECT \"new\" FROM task_ayuza.audit_events WHERE entity_id=:id AND action='task.created'", id=child['id'])[0]['new']
    assert audit_new['parent_task_id'] == str(parent)


def test_d04_checklists(service, acl, items, w, migrator):
    a = join(acl, w, person(service))
    obs = join(acl, w, person(service), 'observer', team=False)
    t = new_task(items, a, w)['id']
    i1 = items.add_checklist_item(a.token, a.csrf, t, 'Step one')
    i2 = items.add_checklist_item(a.token, a.csrf, t, 'Step two')
    assert (i1['position'], i2['position']) == (1, 2)
    assert status(lambda: items.add_checklist_item(obs.token, obs.csrf, t, 'No')) == 404
    assert status(lambda: items.add_checklist_item(a.token, a.csrf, t, ' ')) == 422
    done = items.change_checklist_item(a.token, a.csrf, i1['id'], 1, checked=True)
    assert done['version'] == 2
    row = rows(migrator, 'SELECT is_checked, checked_by, checked_at FROM task_ayuza.checklist_items WHERE id=:id', id=i1['id'])[0]
    assert row['is_checked'] and row['checked_by'] == a.id and row['checked_at'] is not None
    assert rows(migrator, 'SELECT status FROM task_ayuza.tasks WHERE id=:id', id=t)[0]['status'] == 'new'  # never completes the task
    assert items.change_checklist_item(a.token, a.csrf, i1['id'], 2, checked=True)['changed'] is False
    assert status(lambda: items.change_checklist_item(a.token, a.csrf, i1['id'], 1, text='Late')) == 409
    items.change_checklist_item(a.token, a.csrf, i1['id'], 2, text='Step one edited', checked=False)
    items.change_checklist_item(a.token, a.csrf, i2['id'], 1, deleted=True)
    listed = items.list_checklist(a.token, t)
    assert [x['id'] for x in listed] == [i1['id']] and listed[0]['is_checked'] is False
    assert status(lambda: items.list_checklist(w.outsider.token, t)) == 404
    assert status(lambda: items.change_checklist_item(w.outsider.token, w.outsider.csrf, i1['id'], 1, checked=True)) == 404
    dump = repr(rows(migrator, 'SELECT "old","new" FROM task_ayuza.audit_events'))
    assert 'Step one' not in dump and 'Step two' not in dump
    violates(migrator, "UPDATE task_ayuza.checklist_items SET is_checked=true WHERE id=:id", '23514', id=i2['id'])
    violates(migrator, "INSERT INTO task_ayuza.checklist_items (id, workspace_id, task_id, text, position) SELECT gen_random_uuid(), workspace_id, id, 'dup', 1 FROM task_ayuza.tasks WHERE id=:t", '23505', t=t)


def test_d05_comments(service, acl, items, w, migrator):
    author = join(acl, w, person(service))
    other = join(acl, w, person(service))
    obs = join(acl, w, person(service), 'observer', team=True)
    t = new_task(items, author, w, assignee_user_id=other.id)['id']
    c1 = items.add_comment(author.token, author.csrf, t, 'Synthetic comment body')
    assert status(lambda: items.add_comment(obs.token, obs.csrf, t, 'Observer')) == 403     # read only
    assert status(lambda: items.add_comment(w.outsider.token, w.outsider.csrf, t, 'No')) == 404
    assert status(lambda: items.add_comment(author.token, author.csrf, t, '')) == 422
    assert status(lambda: items.edit_comment(other.token, other.csrf, c1['id'], 1, 'Rewrite')) == 403
    edited = items.edit_comment(author.token, author.csrf, c1['id'], 1, 'Synthetic edited body')
    assert edited['version'] == 2
    assert items.edit_comment(author.token, author.csrf, c1['id'], 2, 'Synthetic edited body')['changed'] is False
    assert status(lambda: items.edit_comment(author.token, author.csrf, c1['id'], 1, 'Stale')) == 409
    revisions = rows(migrator, 'SELECT body, version FROM task_ayuza.comment_revisions WHERE comment_id=:cid', cid=c1['id'])
    assert revisions == [{'body': 'Synthetic comment body', 'version': 1}]
    listed = items.list_comments(other.token, t)
    assert [x['body'] for x in listed] == ['Synthetic edited body']
    assert status(lambda: items.list_comments(w.outsider.token, t)) == 404
    # moderation: only through an administrative grant; the text is hidden, not rewritten
    assert status(lambda: items.set_comment_hidden(other.token, other.csrf, c1['id'], True, 2)) == 403
    moderator = person(service)
    join(acl, w, moderator, 'observer', team=False)
    grant(migrator, moderator, w.ws, 'content_edit', w.sysadmin)
    assert status(lambda: items.list_comments(moderator.token, t)) == 404   # moderation grant is not a read grant
    grant(migrator, moderator, w.ws, 'read', w.sysadmin)
    hidden = items.set_comment_hidden(moderator.token, moderator.csrf, c1['id'], True, 2)
    assert hidden['version'] == 3
    assert [x['body'] for x in items.list_comments(other.token, t)] == [None]
    assert [x['body'] for x in items.list_comments(author.token, t)] == ['Synthetic edited body']
    assert [x['body'] for x in items.list_comments(moderator.token, t)] == ['Synthetic edited body']
    assert status(lambda: items.edit_comment(author.token, author.csrf, c1['id'], 3, 'While hidden')) == 409
    restored = items.set_comment_hidden(moderator.token, moderator.csrf, c1['id'], False, 3)
    deleted = items.delete_comment(author.token, author.csrf, c1['id'], restored['version'])
    assert items.list_comments(author.token, t) == []
    assert status(lambda: items.edit_comment(author.token, author.csrf, c1['id'], deleted['version'], 'x')) == 404
    dump = repr(rows(migrator, 'SELECT "old","new" FROM task_ayuza.audit_events'))
    assert 'Synthetic comment body' not in dump and 'Synthetic edited body' not in dump
    for table in ('labels', 'project_stages', 'project_labels', 'task_labels', 'checklist_items', 'comments', 'comment_revisions'):
        violates(service.engine, f'TRUNCATE task_ayuza.{table}', '42501')
        violates(service.engine, f'DELETE FROM task_ayuza.{table} WHERE false', '42501')
    violates(service.engine, "UPDATE task_ayuza.comment_revisions SET body='x' WHERE false", '42501')
