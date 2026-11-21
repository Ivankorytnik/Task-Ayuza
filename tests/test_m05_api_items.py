"""M05.2 tests: /api/v1 labels, stages, checklists, comments, dependencies, blockers, access, history."""
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from test_m01_acl import acl, migrator, person, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join  # noqa: F401
from test_m05_api import ORIGIN, read, task_body, write  # noqa: F401


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


@pytest.fixture(scope='module')
def client():
    with TestClient(app, base_url=ORIGIN, client=('192.0.2.78', 1234)) as c:
        yield c


def post(client, who, path, body):
    return client.post(path, json=body, headers=write(who))


def make_task(client, who, w, project=None):
    body = task_body(w, who, **({'project_id': project} if project else {}))
    return post(client, who, f'/api/v1/workspaces/{w.ws}/tasks', body).json()['id']


def test_l01_items_links_access_and_history(client, service, acl, w):
    a, c = join(acl, w, person(service)), join(acl, w, person(service), team=False)
    project = post(client, a, f'/api/v1/workspaces/{w.ws}/projects', {'title': 'Проект M05.2', 'owner_user_id': str(a.id)}).json()['id']
    t1, t2 = make_task(client, a, w, project), make_task(client, a, w, project)
    # labels
    label = post(client, a, f'/api/v1/workspaces/{w.ws}/labels', {'name': f'м{uuid.uuid4().hex[:6]}'})
    assert label.status_code == 200
    lid = label.json()['id']
    assert client.put(f'/api/v1/tasks/{t1}/labels/{lid}', json={'active': True}, headers=write(a)).status_code == 200
    assert lid in {x['label_id'] if 'label_id' in x else x['id'] for x in client.get(f'/api/v1/tasks/{t1}/labels', headers=read(a)).json()}
    assert client.get(f'/api/v1/workspaces/{w.ws}/labels', headers=read(a)).status_code == 200
    # stages
    stage = post(client, a, f'/api/v1/projects/{project}/stages', {'title': 'Этап 1', 'sort_order': 1})
    assert stage.status_code == 200
    sid = stage.json()['id']
    assert client.get(f'/api/v1/projects/{project}/stages', headers=read(a)).status_code == 200
    assert client.put(f'/api/v1/tasks/{t1}/stage', json={'stage_id': sid, 'expected_version': 1}, headers=write(a)).status_code == 200
    assert client.patch(f'/api/v1/stages/{sid}', json={'expected_version': 1, 'changes': {'title': 'Этап один'}}, headers=write(a)).status_code == 200
    # checklist
    item = post(client, a, f'/api/v1/tasks/{t1}/checklist', {'text': 'Пункт'})
    assert item.status_code == 200
    iid = item.json()['id']
    assert client.patch(f'/api/v1/checklist/{iid}', json={'expected_version': 1, 'checked': True}, headers=write(a)).status_code == 200
    assert client.patch(f'/api/v1/checklist/{iid}', json={'expected_version': 2}, headers=write(a)).status_code == 422   # nothing to change
    assert client.patch(f'/api/v1/checklist/{iid}', json={'expected_version': 2, 'text': None}, headers=write(a)).status_code == 422
    assert len(client.get(f'/api/v1/tasks/{t1}/checklist', headers=read(a)).json()) == 1
    # comments
    comment = post(client, a, f'/api/v1/tasks/{t1}/comments', {'body': 'Первый'})
    cid = comment.json()['id']
    assert client.patch(f'/api/v1/comments/{cid}', json={'expected_version': 1, 'body': 'Правка'}, headers=write(a)).status_code == 200
    assert client.patch(f'/api/v1/comments/{cid}', json={'expected_version': 1, 'body': 'Старая'}, headers=write(a)).status_code == 409
    assert [x['body'] for x in client.get(f'/api/v1/tasks/{t1}/comments', headers=read(a)).json()] == ['Правка']
    assert client.post(f'/api/v1/comments/{cid}/delete', json={'expected_version': 2}, headers=write(a)).status_code == 200
    # dependencies
    dep = post(client, a, '/api/v1/dependencies', {'blocker_task_id': t1, 'dependent_task_id': t2, 'reason': 'сначала первое'})
    assert dep.status_code == 200 and dep.json()['created'] is True
    did = dep.json()['id']
    assert post(client, a, '/api/v1/dependencies', {'blocker_task_id': t2, 'dependent_task_id': t1}).status_code == 422   # cycle
    listed = client.get(f'/api/v1/tasks/{t2}/dependencies', headers=read(a)).json()
    assert listed['edges'][0]['direction'] == 'blocked_by' and listed['hidden_external'] == 0
    assert post(client, a, f'/api/v1/dependencies/{did}/remove', {'expected_version': 1, 'reason': 'не нужно'}).status_code == 200
    assert post(client, a, f'/api/v1/dependencies/{did}/restore', {'expected_version': 2}).status_code == 200
    # blockers
    blocker = post(client, a, f'/api/v1/tasks/{t1}/blockers', {'title': 'Ждём деталь', 'responsible_user_id': str(a.id), 'expected_resolution_date': '2026-12-20'})
    assert blocker.status_code == 200
    bid = blocker.json()['id']
    assert client.patch(f'/api/v1/blockers/{bid}', json={'expected_version': 1, 'changes': {'title': 'Деталь задерживается'}}, headers=write(a)).status_code == 200
    assert post(client, a, f'/api/v1/blockers/{bid}/resolved', {'resolved': True, 'expected_version': 2}).status_code == 200
    assert client.get(f'/api/v1/tasks/{t1}/blockers?include_resolved=false', headers=read(a)).json() == []
    assert [e['event_type'] for e in client.get(f'/api/v1/blockers/{bid}/events', headers=read(a)).json()] == ['created', 'updated', 'resolved']
    assert post(client, a, f'/api/v1/blockers/{bid}/archive', {'archived': True, 'expected_version': 3}).status_code == 200
    # explicit task access and history
    assert client.get(f'/api/v1/tasks/{t1}', headers=read(c)).status_code == 404
    grant = post(client, a, f'/api/v1/tasks/{t1}/access', {'user_id': str(c.id), 'capability': 'read', 'active': True, 'reason': 'просмотр'})
    assert grant.status_code == 200
    assert client.get(f'/api/v1/tasks/{t1}', headers=read(c)).status_code == 200
    assert any(str(c.id) in repr(x) for x in client.get(f'/api/v1/tasks/{t1}/access', headers=read(a)).json())
    assert client.get(f'/api/v1/tasks/{t1}/events', headers=read(a)).status_code == 200


def test_l02_errors_are_safe_on_sub_resources(client, service, acl, w):
    a, other, stranger = join(acl, w, person(service), team=False), join(acl, w, person(service), team=False), person(service)
    hidden = make_task(client, other, w)
    missing = str(uuid.uuid4())
    for suffix in ('comments', 'checklist', 'blockers', 'dependencies', 'labels', 'access', 'events'):
        a_hidden = client.get(f'/api/v1/tasks/{hidden}/{suffix}', headers=read(a))
        a_missing = client.get(f'/api/v1/tasks/{missing}/{suffix}', headers=read(a))
        assert a_hidden.status_code == a_missing.status_code == 404 and a_hidden.json() == a_missing.json(), suffix
        assert client.get(f'/api/v1/tasks/{hidden}/{suffix}', headers=read(stranger)).json() == a_hidden.json()
    assert post(client, a, f'/api/v1/tasks/{hidden}/comments', {'body': 'x'}).status_code == 404
    assert post(client, a, f'/api/v1/tasks/{hidden}/blockers', {'title': 'x', 'responsible_user_id': str(a.id)}).status_code == 404
    mine = make_task(client, a, w)
    assert post(client, a, '/api/v1/dependencies', {'blocker_task_id': mine, 'dependent_task_id': hidden}).status_code == 404
    # CSRF / Origin / malformed input
    path = f'/api/v1/tasks/{mine}/comments'
    assert client.post(path, json={'body': 'x'}, headers=read(a)).status_code == 403
    assert client.post(path, json={'body': 'x'}, headers={**write(a), 'X-CSRF-Token': 'wrong'}).status_code == 403
    assert client.post(path, json={'body': 'x' * 20000}, headers=write(a)).status_code == 422
    assert client.post(path, json={}, headers=write(a)).status_code == 422
    assert client.get('/api/v1/tasks/not-a-uuid/comments', headers=read(a)).status_code == 422
    assert client.get(f'/api/v1/tasks/{mine}/comments').status_code in (401, 403)
