"""M05.3 tests: /api/v1 notifications, risk center, export and release metadata."""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.exports import ExportsService
from backend.main import app
from test_m01_acl import acl, admin_sql, mark_mfa, migrator, person, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import grant, join  # noqa: F401
from test_m04_risks import controller  # noqa: F401
from test_m05_api import ORIGIN, read, task_body, write  # noqa: F401


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


@pytest.fixture(scope='module')
def client():
    with TestClient(app, base_url=ORIGIN, client=('192.0.2.79', 1234)) as c:
        yield c


def post(client, who, path, body):
    return client.post(path, json=body, headers=write(who))


def test_m01_notifications_and_release(client, service, acl, w):
    a, b = join(acl, w, person(service)), join(acl, w, person(service))
    assert client.get('/api/v1/release').status_code in (401, 403)
    info = client.get('/api/v1/release', headers=read(a))
    assert info.status_code == 200 and 'label' in info.json()                      # a real record or "version not determined"
    tid = post(client, a, f'/api/v1/workspaces/{w.ws}/tasks', task_body(w, a)).json()['id']
    assert post(client, a, f'/api/v1/tasks/{tid}/assign', {'expected_version': 1, 'assignee_user_id': str(b.id)}).status_code == 200
    assert client.get('/api/v1/notifications', headers=read(b)).json() == []        # nothing before the outbox runs
    assert ExportsService(service).process_outbox(1000)['created'] >= 1
    items = client.get('/api/v1/notifications', headers=read(b)).json()
    assert [(n['event_type'], n['task_id']) for n in items] == [('task_assigned', tid)]
    assert client.get('/api/v1/notifications/unread-count', headers=read(b)).json() == {'count': 1}
    assert client.get('/api/v1/notifications', headers=read(a)).json() == []
    nid = items[0]['id']
    assert client.post(f'/api/v1/notifications/{nid}/read', headers=read(b)).status_code == 403   # needs CSRF and Origin
    assert client.post(f'/api/v1/notifications/{nid}/read', headers=write(a)).status_code == 404  # not the recipient
    assert client.post(f'/api/v1/notifications/{nid}/read', headers=write(b)).json()['changed'] is True
    assert client.get('/api/v1/notifications/unread-count', headers=read(b)).json() == {'count': 0}
    assert client.get('/api/v1/notifications?limit=0', headers=read(b)).status_code == 422
    assert client.post('/api/v1/outbox/process', headers=write(a)).status_code in (404, 405)       # not exposed


def test_m02_risks_over_http(client, service, acl, w, migrator):
    c, plain = controller(service, migrator), person(service)
    join(acl, w, c, team=False)
    body = {'category': 'backup', 'description': 'Синтетический риск', 'probability': 3, 'impact': 4, 'owner_user_id': str(c.id)}
    assert post(client, plain, '/api/v1/risks', body).status_code == 404            # the area is hidden
    assert client.get('/api/v1/risks', headers=read(plain)).status_code == 404
    created = post(client, c, '/api/v1/risks', body)
    assert created.status_code == 200 and created.json()['control_status'] == 'gray'
    rid = created.json()['id']
    assert client.get(f'/api/v1/risks/{rid}', headers=read(c)).json()['severity'] == 'high'
    assert post(client, c, f'/api/v1/risks/{rid}/checks', {'result': 'pass'}).status_code == 422
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    ok = post(client, c, f'/api/v1/risks/{rid}/checks', {'result': 'pass', 'evidence_reference': 'doc-1', 'valid_until': soon})
    assert ok.status_code == 200 and ok.json()['control_status'] == 'green'
    assert client.get(f'/api/v1/risks/{rid}', headers=read(c)).json()['control_status'] == 'green'
    assert len(client.get(f'/api/v1/risks/{rid}/checks', headers=read(c)).json()) == 1
    assert client.patch(f'/api/v1/risks/{rid}', json={'expected_version': 1, 'changes': {'measures': 'меры'}}, headers=write(c)).status_code == 409   # the check bumped the version
    assert client.patch(f'/api/v1/risks/{rid}', json={'expected_version': 2, 'changes': {'measures': 'меры'}}, headers=write(c)).status_code == 200
    task = post(client, c, f'/api/v1/workspaces/{w.ws}/tasks', task_body(w, c)).json()['id']
    assert client.put(f'/api/v1/risks/{rid}/tasks/{task}', json={'linked': True}, headers=write(c)).status_code == 200
    links = client.get(f'/api/v1/risks/{rid}/links', headers=read(c)).json()
    assert [x['task_id'] for x in links['tasks']] == [task] and links['hidden_tasks'] == 0
    assert post(client, c, f'/api/v1/risks/{rid}/archive', {'archived': True, 'expected_version': 3}).status_code == 200
    assert rid not in [r['id'] for r in client.get('/api/v1/risks', headers=read(c)).json()]
    assert client.get(f'/api/v1/risks/{rid}', headers=read(plain)).status_code == 404
    assert client.get(f'/api/v1/risks/{uuid.uuid4()}', headers=read(c)).status_code == 404


def test_m03_export_over_http(client, service, acl, w, migrator):
    a = join(acl, w, person(service), team=False)
    t = post(client, a, f'/api/v1/workspaces/{w.ws}/tasks', task_body(w, a, title='=1+1 Экспорт')).json()['id']
    assert post(client, a, f'/api/v1/workspaces/{w.ws}/exports', {'format': 'csv'}).status_code == 403   # no export grant
    grant(migrator, a, w.ws, 'export', w.sysadmin)
    csv_out = post(client, a, f'/api/v1/workspaces/{w.ws}/exports', {'format': 'csv'})
    assert csv_out.status_code == 200 and csv_out.headers['content-type'].startswith('text/csv')
    assert 'attachment' in csv_out.headers['content-disposition'] and csv_out.headers['x-export-row-count'] == '1'
    assert csv_out.content.startswith('﻿'.encode('utf-8')) and "'=1+1 Экспорт" in csv_out.content.decode('utf-8')
    as_json = post(client, a, f'/api/v1/workspaces/{w.ws}/exports', {'format': 'json'})
    assert as_json.headers['content-type'].startswith('application/json')
    assert [r['id'] for r in json.loads(as_json.content)] == [t]
    assert post(client, a, f'/api/v1/workspaces/{w.ws}/exports', {'format': 'xml'}).status_code == 422
    assert client.post(f'/api/v1/workspaces/{w.ws}/exports', json={'format': 'csv'}, headers=read(a)).status_code == 403
