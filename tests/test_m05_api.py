"""M05.1 tests: /api/v1 projects and tasks over HTTP. Disposable PostgreSQL, synthetic data only."""
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from test_m01_acl import acl, migrator, person, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join  # noqa: F401

ORIGIN = 'https://test.local'


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


@pytest.fixture(scope='module')
def client():
    with TestClient(app, base_url=ORIGIN, client=('192.0.2.77', 1234)) as c:
        yield c


def read(who):
    return {'Cookie': f'__Host-ay_session={who.token}'}


def write(who):
    return {**read(who), 'Origin': ORIGIN, 'X-CSRF-Token': who.csrf}


def task_body(w, owner, **kw):
    return {'title': 'Синхронная задача', 'result_owner_user_id': str(owner.id), 'executor_team_id': str(w.team), **kw}


def test_k01_project_and_task_flow(client, service, acl, w):
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    pr = client.post(f'/api/v1/workspaces/{w.ws}/projects', json={'title': 'Проект API', 'owner_user_id': str(a.id)}, headers=write(a))
    assert pr.status_code == 200 and pr.headers['cache-control'] == 'no-store'
    pid = pr.json()['id']
    assert client.get(f'/api/v1/projects/{pid}', headers=read(a)).json()['id'] == pid
    assert pid in [p['id'] for p in client.get(f'/api/v1/workspaces/{w.ws}/projects', headers=read(a)).json()]
    key = uuid.uuid4().hex
    t = client.post(f'/api/v1/workspaces/{w.ws}/tasks', json=task_body(w, a, project_id=pid, client_key=key), headers=write(a))
    assert t.status_code == 200
    tid = t.json()['id']
    again = client.post(f'/api/v1/workspaces/{w.ws}/tasks', json=task_body(w, a, project_id=pid, client_key=key), headers=write(a))
    assert again.json()['id'] == tid                                                         # same client_key, same task
    got = client.get(f'/api/v1/tasks/{tid}', headers=read(a)).json()
    assert got['title'] == 'Синхронная задача' and got['version'] == 1
    upd = client.patch(f'/api/v1/tasks/{tid}', json={'expected_version': 1, 'changes': {'title': 'Новое имя', 'due_date': '2026-12-31'}}, headers=write(a))
    assert upd.status_code == 200 and upd.json()['version'] == 2
    stale = client.patch(f'/api/v1/tasks/{tid}', json={'expected_version': 1, 'changes': {'title': 'Старое'}}, headers=write(a))
    assert stale.status_code == 409
    assert client.patch(f'/api/v1/tasks/{tid}', json={'expected_version': 2, 'changes': {'bogus': 1}}, headers=write(a)).status_code == 422
    # assignment: only the given fields change; an explicit null clears the assignee
    asg = client.post(f'/api/v1/tasks/{tid}/assign', json={'expected_version': 2, 'assignee_user_id': str(b.id)}, headers=write(a))
    assert asg.status_code == 200 and asg.json()['version'] == 3
    task = client.get(f'/api/v1/tasks/{tid}', headers=read(a)).json()
    assert task['assignee_user_id'] == str(b.id) and task['result_owner_user_id'] == str(a.id)
    clr = client.post(f'/api/v1/tasks/{tid}/assign', json={'expected_version': 3, 'assignee_user_id': None}, headers=write(a))
    assert clr.status_code == 200
    assert client.get(f'/api/v1/tasks/{tid}', headers=read(a)).json()['assignee_user_id'] is None
    # list with filter and stable pagination
    second = client.post(f'/api/v1/workspaces/{w.ws}/tasks', json=task_body(w, a), headers=write(a)).json()['id']
    walked, after = [], None
    for _ in range(10):
        url = f'/api/v1/workspaces/{w.ws}/tasks?limit=1&status=new' + (f'&after={after}' if after else '')
        page = client.get(url, headers=read(a)).json()
        if not page:
            break
        walked.append(page[0]['id'])
        after = page[0]['id']
    assert sorted(walked) == walked and {tid, second} <= set(walked) and len(set(walked)) == len(walked)
    arch = client.post(f'/api/v1/tasks/{tid}/archive', json={'archived': True, 'expected_version': 4}, headers=write(a))
    assert arch.status_code == 200
    assert tid not in {x['id'] for x in client.get(f'/api/v1/workspaces/{w.ws}/tasks?limit=200', headers=read(a)).json()}


def test_k02_errors_are_safe_and_uniform(client, service, acl, w):
    a, other, stranger = join(acl, w, person(service), team=False), join(acl, w, person(service), team=False), person(service)
    tid = client.post(f'/api/v1/workspaces/{w.ws}/tasks', json=task_body(w, other), headers=write(other)).json()['id']
    # no session, no Origin, wrong CSRF
    assert client.get(f'/api/v1/tasks/{tid}').status_code in (401, 403)
    body = task_body(w, a)
    assert client.post(f'/api/v1/workspaces/{w.ws}/tasks', json=body, headers=read(a)).status_code == 403
    assert client.post(f'/api/v1/workspaces/{w.ws}/tasks', json=body, headers={**write(a), 'X-CSRF-Token': 'wrong'}).status_code == 403
    assert client.post(f'/api/v1/workspaces/{w.ws}/tasks', json=body, headers={**write(a), 'Origin': 'https://evil.test'}).status_code == 403
    # hidden and missing look the same, and nothing hidden is echoed
    hidden = client.get(f'/api/v1/tasks/{tid}', headers=read(a))
    missing = client.get(f'/api/v1/tasks/{uuid.uuid4()}', headers=read(a))
    assert hidden.status_code == missing.status_code == 404 and hidden.json() == missing.json()
    assert client.get(f'/api/v1/tasks/{tid}', headers=read(stranger)).json() == hidden.json()
    assert client.patch(f'/api/v1/tasks/{tid}', json={'expected_version': 1, 'changes': {'title': 'x'}}, headers=write(a)).status_code == 404
    assert client.get(f'/api/v1/workspaces/{w.ws}/tasks', headers=read(stranger)).status_code == 404
    listed = client.get(f'/api/v1/workspaces/{w.ws}/tasks?limit=200', headers=read(a)).json()
    assert tid not in {x['id'] for x in listed}
    # malformed input
    assert client.get('/api/v1/tasks/not-a-uuid', headers=read(a)).status_code == 422
    assert client.get(f'/api/v1/workspaces/{w.ws}/tasks?limit=0', headers=read(a)).status_code == 422
    assert client.get(f'/api/v1/workspaces/{w.ws}/tasks?status=bogus', headers=read(a)).status_code == 422
    bad = client.post(f'/api/v1/workspaces/{w.ws}/tasks', json={'title': 'x' * 5000}, headers=write(a))
    assert bad.status_code == 422 and 'xxxx' not in bad.text
    for path in ('/api/v1/users', '/api/v1/admin/tasks', f'/api/v1/tasks/{tid}/delete'):
        assert client.post(path, json={}, headers=write(a)).status_code in (404, 405)
