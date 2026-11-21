"""M06.1 tests: the static client is served from the same origin with safe headers and without storage or
external hosts."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.main import WEB_DIR, app
from test_m01_auth import service  # noqa: F401
from test_m05_api import ORIGIN


@pytest.fixture(scope='module')
def client():
    with TestClient(app, base_url=ORIGIN, client=('192.0.2.81', 1234)) as c:
        yield c


def test_n01_static_client_and_headers(client, service):
    root = client.get('/', follow_redirects=False)
    assert root.status_code in (302, 307) and root.headers['location'] == '/app/'
    page = client.get('/app/')
    assert page.status_code == 200 and page.headers['content-type'].startswith('text/html')
    csp = page.headers['content-security-policy']
    assert "script-src 'self'" in csp and "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and 'unsafe' not in csp
    assert page.headers['x-content-type-options'] == 'nosniff' and page.headers['referrer-policy'] == 'same-origin'
    assert page.headers['cache-control'] == 'no-store'
    for path, kind in (('app.js', 'javascript'), ('logic.js', 'javascript'), ('styles.css', 'css'),
                       ('manifest.webmanifest', 'json'), ('icon.svg', 'svg')):
        response = client.get(f'/app/{path}')
        assert response.status_code == 200 and kind in response.headers['content-type'], path
    assert client.get('/app/missing.js').status_code == 404
    assert client.get('/app/../backend/auth.py').status_code in (400, 404)
    assert client.get('/app/%2e%2e/backend/auth.py').status_code in (400, 404)
    api = client.get('/api/v1/auth/me')
    assert 'content-security-policy' not in api.headers and api.headers['x-content-type-options'] == 'nosniff'


def test_n02_client_sources_are_safe():
    html = (WEB_DIR / 'index.html').read_text(encoding='utf-8')
    assert not re.search(r'<script(?![^>]*\bsrc=)[^>]*>', html) and 'onclick' not in html and 'style=' not in html
    for path in WEB_DIR.iterdir():
        if path.suffix not in ('.js', '.html', '.css', '.webmanifest') or path.name == 'test_client.js':
            continue
        text = path.read_text(encoding='utf-8')
        assert 'localStorage' not in text and 'sessionStorage' not in text and 'indexedDB' not in text, path.name
        assert 'innerHTML' not in text and 'outerHTML' not in text and 'eval(' not in text and 'document.write' not in text, path.name
        assert not re.search(r'https?://', text), path.name                         # no external hosts
    assert (WEB_DIR / 'package.json').read_text() == '{"type":"module"}\n'
    assert 'COPY web web' in (Path(WEB_DIR).parent / 'Dockerfile').read_text()


def test_n03_client_views_use_api_only():
    app = (WEB_DIR / 'app.js').read_text(encoding='utf-8')
    logic = (WEB_DIR / 'logic.js').read_text(encoding='utf-8')
    assert 'boardView' in app and 'notesView' in app and 'blockersView' in app
    assert 'draggable' in app and 'dragover' in app                       # Kanban moves go through Api.updateTask with a version
    assert 'api.updateTask(id, version, { status: to })' in app
    for path in ('/api/v1/notifications', '/api/v1/tasks/${id}/blockers', '/api/v1/tasks/${id}/dependencies'):
        assert path in logic, path
    assert app.count('fetch(') == 1                                         # one injection point into Api, no direct calls


def test_n04_risk_and_export_views():
    app = (WEB_DIR / 'app.js').read_text(encoding='utf-8')
    logic = (WEB_DIR / 'logic.js').read_text(encoding='utf-8')
    assert 'risksView' in app and 'exportTasks' in app and 'riskCard' in app
    assert '/api/v1/risks' in logic and '/exports' in logic and '/api/v1/release' in logic
    assert 'Blob' in app and 'createObjectURL' in app                        # the export is saved locally, never kept in storage


def test_n05_nested_children_are_flattened_fully():
    app = (WEB_DIR / 'app.js').read_text(encoding='utf-8')
    assert 'children.flat(Infinity)' in app          # found in a real browser: nested arrays rendered as [object HTMLDivElement]
    assert '[object' not in app


def test_n06_links_views_use_api():
    app = (WEB_DIR / 'app.js').read_text(encoding='utf-8')
    logic = (WEB_DIR / 'logic.js').read_text(encoding='utf-8')
    assert 'resolveBlocker' in app and 'removeDependency' in app and 'linkRiskTask' in app and 'dependencyPayload' in app
    for path in ('/api/v1/blockers/${id}/resolved', '/api/v1/dependencies', '/api/v1/risks/${riskId}/tasks/${taskId}'):
        assert path in logic, path
