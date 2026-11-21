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
