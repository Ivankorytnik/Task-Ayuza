"""M06.0 tests: workspace list and directory for the client."""
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from test_m01_acl import acl, migrator, person, world  # noqa: F401
from test_m01_auth import service  # noqa: F401
from test_m02_work import join  # noqa: F401
from test_m05_api import ORIGIN, read


@pytest.fixture(scope='module')
def w(service, acl, migrator):
    return world(service, acl, migrator)


@pytest.fixture(scope='module')
def client():
    with TestClient(app, base_url=ORIGIN, client=('192.0.2.80', 1234)) as c:
        yield c


def test_m01_directory_for_members_only(client, service, acl, w, migrator):
    member, solo, stranger = join(acl, w, person(service)), join(acl, w, person(service), team=False), person(service)
    listed = client.get('/api/v1/workspaces', headers=read(member)).json()
    assert w.ws in {str(x['id']) for x in listed}
    assert client.get('/api/v1/workspaces', headers=read(stranger)).json() == []
    d = client.get(f'/api/v1/workspaces/{w.ws}/directory', headers=read(member))
    assert d.status_code == 200 and d.headers['cache-control'] == 'no-store'
    body = d.json()
    assert str(w.team) in [t['id'] for t in body['teams']] and str(w.team) in body['my_team_ids']
    assert {str(member.id), str(solo.id)} <= {m['user_id'] for m in body['members']}
    assert set(body['members'][0]) == {'user_id', 'display_name', 'role'}                 # no login or other account data
    assert client.get(f'/api/v1/workspaces/{w.ws}/directory', headers=read(solo)).json()['my_team_ids'] == []
    missing = client.get('/api/v1/workspaces/00000000-0000-4000-8000-000000000000/directory', headers=read(member))
    hidden = client.get(f'/api/v1/workspaces/{w.ws}/directory', headers=read(stranger))
    assert hidden.status_code == missing.status_code == 404 and hidden.json() == missing.json()
    assert client.get(f'/api/v1/workspaces/{w.ws}/directory').status_code in (401, 403)
