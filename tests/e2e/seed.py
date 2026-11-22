"""Seeds one synthetic user with a workspace, team and a few tasks for the browser E2E. Synthetic data only.
Run from the repository root against the disposable local-stack database; prints JSON with the login and password."""
import json
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]

from sqlalchemy import create_engine  # noqa: E402

from backend.acl import AclService  # noqa: E402
from backend.auth import AuthService, execute  # noqa: E402
from backend.exports import ExportsService  # noqa: E402
from test_m01_acl import Who, _ip, world  # noqa: E402
from test_m01_auth import PASSWORD, user  # noqa: E402
from test_m02_work import join, new_task  # noqa: E402
from types import SimpleNamespace  # noqa: E402

NEW_PASSWORD = 'Synthetic другой пароль 4712!'


def sign_in_as(service, login, password):
    pre = service.prelogin(ip=_ip())
    return service.login(login, password, _ip(), pre['token'], pre['csrf_token'])


def execute_sql(engine, statement, **params):
    with engine.begin() as c:
        execute(c, statement, **params)


def main():
    runtime = create_engine(os.environ['TASK_AYUZA_DATABASE_URL'], hide_parameters=True)
    migrator = create_engine('postgresql+psycopg://task_ayuza_migrator:%s@%s:%s/task_ayuza_test' % (
        os.environ['TA_MIGRATOR_PW'], os.environ.get('TA_DB_HOST', '127.0.0.1'), os.environ.get('TA_DB_PORT', '5432')),
        hide_parameters=True)
    with migrator.begin() as c:                                               # the acceptance runner does the same in its fixture
        execute(c, "INSERT INTO task_ayuza.organization (id, name) VALUES (:id, 'Synthetic') ON CONFLICT DO NOTHING", id=uuid.uuid4())
    service = AuthService(runtime, bytes.fromhex(os.environ['TASK_AYUZA_AUTH_HMAC_KEY']))
    acl, work = AclService(service), ExportsService(service)
    uid, login, temporary = user(service)

    def sign_in(password):
        pre = service.prelogin(ip=_ip())
        return service.login(login, password, _ip(), pre['token'], pre['csrf_token'])

    first = sign_in(temporary)
    service.change_password(first['token'], first['csrf_token'], PASSWORD)     # the browser signs in with the durable password
    me = Who(uid, sign_in(PASSWORD))
    w = world(service, acl, migrator)
    join(acl, w, me)
    # a user who still has the temporary password: the browser must change it
    t_uid, t_login, t_temporary = user(service)
    join(acl, w, SimpleNamespace(id=t_uid))
    # a risk controller with a normal password (role through the migrator, like the acceptance tests)
    c_uid, c_login, c_temporary = user(service)
    c_first = sign_in_as(service, c_login, c_temporary)
    service.change_password(c_first['token'], c_first['csrf_token'], PASSWORD)
    execute_sql(migrator, "INSERT INTO task_ayuza.system_role_assignments (id, user_id, role_code, reason) "
                          "VALUES (:id, :u, 'risk_controller', 'synthetic e2e')", id=uuid.uuid4(), u=c_uid)
    join(acl, w, SimpleNamespace(id=c_uid))
    for title in ('Синтетическая задача 1', 'Синтетическая задача 2'):
        new_task(work, me, w, title=title)
    print(json.dumps({'login': login, 'password': PASSWORD, 'workspace': str(w.ws),
                      'temp': {'login': t_login, 'temporary': t_temporary, 'new_password': NEW_PASSWORD},
                      'controller': {'login': c_login, 'password': PASSWORD, 'id': str(c_uid)}}))


if __name__ == '__main__':
    main()
