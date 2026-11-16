"""M01.2 tests run only by the disposable loopback acceptance runner."""
import json
import resource
import os
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Lock
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

import backend.auth as auth_module
from backend.auth import AuthService, AuthError, digest, execute, one, clock
from backend.main import app
from backend.passwords import HASHER, normalize_login, validate_password
from test_m01_foundation import _test_url

PASSWORD='Synthetic durable пароль 908!'


@pytest.fixture(scope='module')
def service():
    engine=create_engine(_test_url('TASK_AYUZA_TEST_RUNTIME_URL'),hide_parameters=True,pool_size=20,max_overflow=10)
    svc=AuthService(engine,bytes.fromhex(os.environ['TASK_AYUZA_AUTH_HMAC_KEY']))
    yield svc
    engine.dispose()


def user(service):
    with service.engine.connect() as c:
        org=execute(c,'SELECT id FROM task_ayuza.organization').scalar_one()
    login='test_'+uuid.uuid4().hex
    uid,pw=service.create_user(org,login,'Synthetic')
    return uid,login,pw


def login(service,name,pw,ip='192.0.2.1'):
    pre=service.prelogin(ip='192.0.2.' + str(secrets.randbelow(220)+10))
    return service.login(name,pw,ip,pre['token'],pre['csrf_token'])


def normal(service):
    uid,name,pw=user(service)
    s=login(service,name,pw)
    service.change_password(s['token'],s['csrf_token'],PASSWORD)
    return uid,name,login(service,name,PASSWORD)


def read_user(service,uid):
    with service.engine.connect() as c:
        return one(c,'SELECT * FROM task_ayuza.users WHERE id=:id',id=uid)


def rejected(fn,status=401):
    with pytest.raises(AuthError) as e:
        fn()
    assert e.value.status==status


def test_policy_and_argon_measurement():
    assert normalize_login('  AbC._-  ')=='abc._-'
    for name in ('ab','a'*65,'пароль','ＡBC','ab c','Key'):
        with pytest.raises(ValueError): normalize_login(name)
    for pw in ('short','passwordpassword','x'*129):
        with pytest.raises(ValueError): validate_password(pw)
    validate_password('   Unicode пароль   ')
    durations=[]
    for _ in range(3):
        t=time.perf_counter(); encoded=HASHER.hash(PASSWORD); durations.append(time.perf_counter()-t)
        assert '$argon2id$v=19$m=65536,t=3,p=1$' in encoded
        assert HASHER.verify(encoded,PASSWORD)
        assert not auth_module.verify(encoded,PASSWORD+' ')
    with ThreadPoolExecutor(max_workers=4) as pool:
        t=time.perf_counter(); list(pool.map(HASHER.hash,[PASSWORD]*4)); parallel=time.perf_counter()-t
    print(f'ARGON2 single_seconds={durations}; four_concurrent_seconds={parallel:.3f}; configured_memory=64MiB/operation; process_peak_RSS_KiB={resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}',flush=True)


def test_temporary_lifecycle_and_uniqueness(service):
    uid,name,pw=user(service)
    assert len(pw)==24
    u=read_user(service,uid)
    assert u['login']==name and u['password_hash']!=pw
    with service.engine.connect() as c:
        remaining=u['temporary_expires_at']-clock(c)
    assert timedelta(hours=23)<remaining<=timedelta(hours=24)
    s=login(service,'  '+name.upper()+' ',pw)
    assert s['kind']=='password'
    rejected(lambda:service.me(s['token']),403)
    rejected(lambda:service.renew(s['token'],s['csrf_token']),403)
    with service.engine.connect() as c:
        row=one(c,'SELECT * FROM task_ayuza.sessions WHERE id=:id',id=s['session_id'])
    assert row['expires_at']-row['created_at']<=timedelta(minutes=10)
    assert row['expires_at']<=u['temporary_expires_at']
    service.change_password(s['token'],s['csrf_token'],PASSWORD)
    rejected(lambda:service.me(s['token']))
    n=login(service,name,PASSWORD)
    assert service.me(n['token'])['id']==str(uid)
    service.deactivate(uid)
    rejected(lambda:service.me(n['token']))
    with pytest.raises(AuthError): service.create_user(u['organization_id'],' '+name.upper()+' ','Duplicate')
    assert read_user(service,uid)['auth_version']==3


def test_session_deadlines_renewal_logout_and_no_raw_secrets(service):
    uid,name,s=normal(service)
    with service.engine.connect() as c:
        before=one(c,'SELECT * FROM task_ayuza.sessions WHERE id=:id',id=s['session_id'])
    assert before['absolute_expires_at']-before['created_at']==timedelta(hours=8)
    assert before['expires_at']-before['created_at']==timedelta(minutes=30)
    service.me(s['token'])
    with service.engine.connect() as c:
        assert one(c,'SELECT expires_at FROM task_ayuza.sessions WHERE id=:id',id=s['session_id'])['expires_at']==before['expires_at']
    service.renew(s['token'],s['csrf_token'])
    with service.engine.connect() as c:
        after=one(c,'SELECT * FROM task_ayuza.sessions WHERE id=:id',id=s['session_id'])
        audit=json.dumps([dict(r) for r in execute(c,'SELECT * FROM task_ayuza.audit_events').mappings()],default=str)
    assert before['token_hash']==after['token_hash']==digest(s['token'])
    assert after['expires_at']<=before['absolute_expires_at']
    for secret in (s['token'],s['csrf_token'],PASSWORD,read_user(service,uid)['password_hash']): assert secret not in audit
    other=login(service,name,PASSWORD)
    service.logout(s['token'],s['csrf_token'])
    rejected(lambda:service.me(s['token']))
    assert service.me(other['token'])['id']==str(uid)
    service.reset_password(uid)
    rejected(lambda:service.me(other['token']))


@pytest.mark.parametrize('kind',['idle','absolute','temporary','prelogin'])
def test_expiry(service,kind):
    uid,name,pw=user(service)
    if kind=='prelogin':
        s=service.prelogin(ip='192.0.2.' + str(secrets.randbelow(220)+10))
    else:
        s=login(service,name,pw)
        if kind!='temporary':
            service.change_password(s['token'],s['csrf_token'],PASSWORD)
            s=login(service,name,PASSWORD)
    with service.engine.begin() as c:
        # Synthetic clock displacement preserving SQL constraints.
        execute(c,"UPDATE task_ayuza.sessions SET created_at=created_at-interval '9 hours',expires_at=expires_at-interval '9 hours',absolute_expires_at=absolute_expires_at-interval '9 hours' WHERE id=:id",id=s['session_id'])
        if kind=='temporary':
            execute(c,"UPDATE task_ayuza.users SET temporary_expires_at=clock_timestamp()-interval '1 second' WHERE id=:id",id=uid)
    if kind=='prelogin':
        rejected(lambda:service.login(name,pw,'192.0.2.2',s['token'],s['csrf_token']))
    elif kind=='temporary':
        rejected(lambda:service.change_password(s['token'],s['csrf_token'],PASSWORD))
        rejected(lambda:login(service,name,pw))
    else:
        rejected(lambda:service.me(s['token']))
        rejected(lambda:service.renew(s['token'],s['csrf_token']))


def test_unknown_wrong_inactive_equal_and_dummy(service):
    uid,name,pw=user(service)
    unknown='absent_'+uuid.uuid4().hex
    with patch('backend.auth.verify',wraps=auth_module.verify) as check:
        rejected(lambda:login(service,unknown,pw,'192.0.2.3'))
        assert check.call_count==1 and check.call_args.args[0]==service.dummy_hash
    rejected(lambda:login(service,name,'wrong','192.0.2.3'))
    service.deactivate(uid)
    rejected(lambda:login(service,name,pw,'192.0.2.3'))


def test_limiter_concurrent_and_persistent(service):
    name='limited_'+uuid.uuid4().hex
    barrier=Barrier(12)
    def attempt(i):
        barrier.wait(timeout=10)
        try:
            service.reserve(name,'198.51.100.1',uuid.uuid4()); return True
        except AuthError as e:
            assert e.status==429; return False
    with ThreadPoolExecutor(max_workers=12) as pool:
        results=list(pool.map(attempt,range(12)))
    assert sum(results)==5
    with service.engine.connect() as c:
        assert execute(c,"SELECT count(*) FROM task_ayuza.audit_events WHERE action='auth.login_limited' AND request_id IS NOT NULL").scalar_one() >= 1
        marker=one(c,"SELECT last_event_at FROM task_ayuza.auth_limit_events WHERE key_kind='login' AND key_hash=:key",
                   key=service.key('login',name))
        assert marker is not None
    other=AuthService(service.engine,service.hmac_key)
    rejected(lambda:other.reserve(name,'198.51.100.2',uuid.uuid4()),429)
    with create_engine(_test_url('TASK_AYUZA_TEST_MIGRATOR_URL'),hide_parameters=True).begin() as c:
        execute(c,"UPDATE task_ayuza.login_attempts SET attempted_at=attempted_at-interval '16 minutes' WHERE login_key=:key",key=service.key('login',name))
    other.reserve(name,'198.51.100.2',uuid.uuid4())
    # Independent IP threshold: 100 distinct logins; never Argon on reservation.
    ip='198.51.100.3'
    for i in range(100): service.reserve(f'ip-limit-{i}',ip,uuid.uuid4())
    rejected(lambda:other.reserve('new-ip-limit',ip,uuid.uuid4()),429)


def test_login_normalization_and_no_success_reset(service):
    uid,name,pw=user(service)
    for i in range(5): login(service,' '+name.upper()+' ',pw,'203.0.113.2')
    pre=service.prelogin(ip='192.0.2.' + str(secrets.randbelow(220)+10))
    with patch('backend.auth.verify',side_effect=AssertionError('Argon must not execute')):
        rejected(lambda:service.login(name,pw,'203.0.113.3',pre['token'],pre['csrf_token']),429)


def race_users(service,functions):
    """Force two independent PostgreSQL transactions to meet before user lock."""
    barrier=Barrier(2)
    pids=set(); guard=Lock()
    original=auth_module.one
    def synchronized(c,sql,**params):
        if 'task_ayuza.users' in sql and 'FOR UPDATE' in sql:
            pid=c.connection.driver_connection.info.backend_pid
            with guard:pids.add(pid)
            barrier.wait(timeout=10)
        return original(c,sql,**params)
    def run(fn):
        try:return fn()
        except AuthError as e:return e
    with patch('backend.auth.one',side_effect=synchronized):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(run,fn) for fn in functions]
            results=[f.result(timeout=30) for f in futures]
    assert len(pids)==2
    return results


@pytest.mark.parametrize('action',['reset','deactivate'])
def test_race_login_against_invalidation(service,action):
    uid,name,pw=user(service)
    pre=service.prelogin(ip='192.0.2.' + str(secrets.randbelow(220)+10))
    change=service.reset_password if action=='reset' else service.deactivate
    results=race_users(service,[lambda:service.login(name,pw,'203.0.113.4',pre['token'],pre['csrf_token']),lambda:change(uid)])
    if isinstance(results[0],dict):rejected(lambda:service.me(results[0]['token']))
    with service.engine.connect() as c:
        assert execute(c,'''SELECT count(*) FROM task_ayuza.sessions s JOIN task_ayuza.users u ON u.id=s.user_id
            WHERE u.id=:id AND s.revoked_at IS NULL AND s.auth_version=u.auth_version''',id=uid).scalar_one()==0


def test_race_renew_against_revoke(service):
    uid,name,s=normal(service)
    race_users(service,[lambda:service.renew(s['token'],s['csrf_token']),lambda:service.logout(s['token'],s['csrf_token'])])
    rejected(lambda:service.me(s['token']))


def test_race_double_temporary_change(service):
    uid,name,pw=user(service);s=login(service,name,pw)
    results=race_users(service,[lambda:service.change_password(s['token'],s['csrf_token'],PASSWORD),lambda:service.change_password(s['token'],s['csrf_token'],PASSWORD+'2')])
    assert sum(isinstance(r,AuthError) for r in results)==1
    with service.engine.connect() as c:
        assert execute(c,"SELECT count(*) FROM task_ayuza.audit_events WHERE entity_id=:id AND action='auth.password_changed'",id=uid).scalar_one()==1
    assert read_user(service,uid)['auth_version']==2


def test_race_revoke_protected_operation(service):
    uid,name,s=normal(service)
    def operation(c,u,session):
        assert session['revoked_at'] is None
        execute(c,'UPDATE task_ayuza.users SET display_name=:name WHERE id=:id',name='Protected synthetic',id=uid)
        auth_module.event(c,'renewed',user_id=uid,session_id=session['id'],request_id=uuid.uuid4())
    race_users(service,[lambda:service.protected(s['token'],operation,csrf=s['csrf_token'],mutation=True),lambda:service.logout(s['token'],s['csrf_token'])])
    rejected(lambda:service.protected(s['token'],operation,csrf=s['csrf_token'],mutation=True))
    # Explicit revoke-first order: callback cannot run after completed revocation.
    called=[]
    rejected(lambda:service.protected(s['token'],lambda *args:called.append(True)))
    assert not called


def test_audit_failure_rolls_back(service):
    uid,name,s=normal(service)
    before=read_user(service,uid)
    original=auth_module.event
    def broken(c,*args,**kwargs):
        original(c,*args,**kwargs)
        # Actual database rejection, not a mocked Python-only error.
        execute(c,'''INSERT INTO task_ayuza.audit_events
            (id,actor_kind,entity_kind,entity_id,action,request_id,"new")
            VALUES (:id,'system','user',:user,'auth.password_reset',:req,'{"token":"forbidden"}'::jsonb)''',
            id=uuid.uuid4(),user=uid,req=uuid.uuid4())
    with patch('backend.auth.event',side_effect=broken):
        rejected(lambda:service.reset_password(uid),503)
        rejected(lambda:service.deactivate(uid),503)
        rejected(lambda:service.change_password(s['token'],s['csrf_token'],PASSWORD+'2',PASSWORD),503)
        rejected(lambda:service.logout(s['token'],s['csrf_token']),503)
        rejected(lambda:service.renew(s['token'],s['csrf_token']),503)
    assert dict(read_user(service,uid))==dict(before)
    assert service.me(s['token'])['id']==str(uid)


def test_retry_rollback_and_limit(service):
    uid,name,s=normal(service)
    request=uuid.uuid4(); calls=[]
    def transient(c):
        calls.append(1)
        auth_module.event(c,'renewed',user_id=uid,session_id=s['session_id'],request_id=request)
        if len(calls)<3:
            execute(c,"DO $$ BEGIN RAISE EXCEPTION 'synthetic' USING ERRCODE='40001'; END $$")
    service.transaction(transient)
    assert len(calls)==3
    with service.engine.connect() as c:
        assert execute(c,'SELECT count(*) FROM task_ayuza.audit_events WHERE request_id=:id',id=request).scalar_one()==1
    for code in ('40001','40P01'):
        calls.clear()
        def always(c):
            calls.append(1)
            execute(c,f"DO $$ BEGIN RAISE EXCEPTION 'synthetic' USING ERRCODE='{code}'; END $$")
        rejected(lambda:service.transaction(always),503)
        assert len(calls)==3


def test_cleanup_preserves_audit(service):
    pre=service.prelogin(ip='192.0.2.' + str(secrets.randbelow(220)+10));name='cleanup_'+uuid.uuid4().hex
    service.reserve(name,'203.0.113.5',uuid.uuid4())
    with create_engine(_test_url('TASK_AYUZA_TEST_MIGRATOR_URL'),hide_parameters=True).begin() as c:
        audit=execute(c,'SELECT count(*) FROM task_ayuza.audit_events').scalar_one()
        execute(c,"UPDATE task_ayuza.sessions SET created_at=created_at-interval '26 hours',expires_at=expires_at-interval '26 hours',absolute_expires_at=absolute_expires_at-interval '26 hours' WHERE id=:id",id=pre['session_id'])
        execute(c,"UPDATE task_ayuza.login_attempts SET attempted_at=attempted_at-interval '25 hours' WHERE login_key=:key",key=service.key('login',name))
    service.cleanup()
    with service.engine.connect() as c:
        assert execute(c,'SELECT count(*) FROM task_ayuza.audit_events').scalar_one()==audit
        assert not one(c,'SELECT id FROM task_ayuza.sessions WHERE id=:id',id=pre['session_id'])
        assert not one(c,'SELECT id FROM task_ayuza.login_attempts WHERE login_key=:key',key=service.key('login',name))


def test_http_cookie_csrf_origin_errors_no_store(service):
    uid,name,pw=user(service)
    with TestClient(app,base_url='https://test.local',client=('192.0.2.90',1234)) as client:
        assert client.get('/api/v1/auth/prelogin').status_code==403
        pre=client.get('/api/v1/auth/prelogin',headers={'Origin':'https://test.local'})
        assert pre.status_code==200
        cookie=pre.headers['set-cookie']
        for value in ('__Host-ay_session=','Secure','HttpOnly','SameSite=lax','Path=/'):assert value in cookie
        assert 'Domain=' not in cookie
        csrf=pre.json()['csrf_token'];data={'login':name,'password':pw}
        for headers in ({},{'Origin':'https://evil.test','X-CSRF-Token':csrf},{'Origin':'https://test.local'},
                        {'Referer':'https://test.local.evil/path','X-CSRF-Token':csrf},
                        {'Origin':'null','Referer':'https://test.local/path','X-CSRF-Token':csrf},
                        {'Origin':'https://test.local','X-CSRF-Token':'wrong'}):
            response=client.post('/api/v1/auth/login',json=data,headers=headers)
            assert response.status_code==403 and response.headers['cache-control']=='no-store'
        response=client.post('/api/v1/auth/login',json=data,headers={'Referer':'https://test.local/path','X-CSRF-Token':csrf})
        assert response.status_code==200
        assert client.get('/api/v1/auth/me').status_code==403
        headers={'Origin':'https://test.local','X-CSRF-Token':response.json()['csrf_token']}
        bad=client.post('/api/v1/auth/password',json={'new_password':'secret'*30},headers=headers)
        assert bad.status_code==422 and 'secret' not in bad.text
        response=client.post('/api/v1/auth/password',json={'new_password':PASSWORD},headers=headers)
        assert response.status_code==200 and response.json()['login_required']
        assert client.get('/api/v1/auth/me').status_code==401
        for path in ('/api/v1/users','/api/v1/auth/reset','/api/v1/admin/users'):
            assert client.post(path,json={}).status_code==404


def test_password_session_capped_by_temporary_deadline(service):
    uid,name,pw=user(service)
    with service.engine.begin() as c:
        execute(c,"UPDATE task_ayuza.users SET temporary_expires_at=clock_timestamp()+interval '2 minutes' WHERE id=:id",id=uid)
    s=login(service,name,pw)
    with service.engine.connect() as c:
        row=one(c,'SELECT * FROM task_ayuza.sessions WHERE id=:id',id=s['session_id'])
    assert row['absolute_expires_at']==read_user(service,uid)['temporary_expires_at']
    assert row['expires_at']-row['created_at']<=timedelta(minutes=2)


def test_renew_cannot_exceed_absolute_or_resurrect_idle(service):
    uid,name,s=normal(service)
    with service.engine.begin() as c:
        execute(c,"UPDATE task_ayuza.sessions SET expires_at=clock_timestamp()+interval '1 minute',absolute_expires_at=clock_timestamp()+interval '2 minutes' WHERE id=:id",id=s['session_id'])
    service.renew(s['token'],s['csrf_token'])
    with service.engine.begin() as c:
        row=one(c,'SELECT * FROM task_ayuza.sessions WHERE id=:id',id=s['session_id'])
        assert row['expires_at']==row['absolute_expires_at']
        execute(c,"UPDATE task_ayuza.sessions SET created_at=created_at-interval '31 minutes',expires_at=clock_timestamp()-interval '1 second' WHERE id=:id",id=s['session_id'])
    rejected(lambda:service.renew(s['token'],s['csrf_token']))


def test_prelogin_destroyed_and_all_mutations_require_csrf(service):
    uid,name,pw=user(service);pre=service.prelogin(ip='192.0.2.' + str(secrets.randbelow(220)+10))
    s=service.login(name,pw,'192.0.2.91',pre['token'],pre['csrf_token'])
    with service.engine.connect() as c:
        assert not one(c,'SELECT id FROM task_ayuza.sessions WHERE id=:id',id=pre['session_id'])
    for fn in (lambda:service.logout(s['token'],''),lambda:service.renew(s['token'],''),
               lambda:service.change_password(s['token'],'',PASSWORD),
               lambda:service.protected(s['token'],lambda *a:None,mutation=True)):
        rejected(fn,403)
    rejected(lambda:service.change_password(s['token'],pre['csrf_token'],PASSWORD),403)


def test_login_and_creation_rollback_when_audit_denied(service):
    uid,name,pw=user(service);pre=service.prelogin(ip='192.0.2.' + str(secrets.randbelow(220)+10))
    with service.engine.connect() as c:
        users=execute(c,'SELECT count(*) FROM task_ayuza.users').scalar_one()
        sessions=execute(c,'SELECT count(*) FROM task_ayuza.sessions').scalar_one()
    def failure(c,*args,**kwargs):
        execute(c,"DO $$ BEGIN RAISE EXCEPTION 'synthetic audit rejection' USING ERRCODE='23514'; END $$")
    with patch('backend.auth.event',side_effect=failure):
        rejected(lambda:service.login(name,pw,'192.0.2.92',pre['token'],pre['csrf_token']),503)
        with service.engine.connect() as c:org=execute(c,'SELECT id FROM task_ayuza.organization').scalar_one()
        rejected(lambda:service.create_user(org,'rollback_'+uuid.uuid4().hex,'Synthetic'),503)
    with service.engine.connect() as c:
        assert execute(c,'SELECT count(*) FROM task_ayuza.users').scalar_one()==users
        assert execute(c,'SELECT count(*) FROM task_ayuza.sessions').scalar_one()==sessions
        assert one(c,'SELECT id FROM task_ayuza.sessions WHERE id=:id',id=pre['session_id'])
        assert execute(c,'SELECT count(*) FROM task_ayuza.login_attempts WHERE login_key=:key',key=service.key('login',name)).scalar_one()==1


def test_real_postgresql_deadlock_retry(service):
    barrier=Barrier(2);pids=set();guard=Lock()
    requests=[uuid.uuid4(),uuid.uuid4()]
    uid,name,s=normal(service)
    def work(i):
        attempts=0
        def operation(c):
            nonlocal attempts
            attempts+=1
            with guard:
                if attempts==1:pids.add(c.connection.driver_connection.info.backend_pid)
            execute(c,'SELECT pg_advisory_xact_lock(:key)',key=731001+i)
            if attempts==1:barrier.wait(timeout=10)
            execute(c,'SELECT pg_advisory_xact_lock(:key)',key=731002-i)
            auth_module.event(c,'renewed',user_id=uid,session_id=s['session_id'],request_id=requests[i])
        service.transaction(operation)
        return attempts
    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts=list(pool.map(work,range(2)))
    assert sorted(attempts)==[1,2] and len(pids)==2
    with service.engine.connect() as c:
        for request in requests:
            assert execute(c,'SELECT count(*) FROM task_ayuza.audit_events WHERE request_id=:id',id=request).scalar_one()==1


def test_parallel_ip_limit(service):
    ip='198.51.100.200'
    for i in range(95):service.reserve(f'parallel-ip-seed-{i}',ip,uuid.uuid4())
    barrier=Barrier(10)
    def work(i):
        barrier.wait(timeout=10)
        try:service.reserve(f'parallel-ip-{i}',ip,uuid.uuid4());return True
        except AuthError as e:
            assert e.status==429;return False
    with ThreadPoolExecutor(max_workers=10) as pool:results=list(pool.map(work,range(10)))
    assert sum(results)==5


def test_prelogin_abuse_concurrency_and_csrf_reload(service):
    ip='203.0.113.220'
    barrier=Barrier(40)
    def get_pre(i):
        barrier.wait(timeout=20)
        try:return service.prelogin(ip=ip)
        except AuthError as e:
            assert e.status==429
            return None
    with ThreadPoolExecutor(max_workers=40) as pool:
        results=list(pool.map(get_pre,range(40)))
    assert sum(r is not None for r in results)==30
    with service.engine.connect() as c:
        assert execute(c,"SELECT count(*) FROM task_ayuza.prelogin_limits WHERE ip_key=:key",
                       key=service.key('prelogin-ip',ip)).scalar_one()==1
        assert execute(c,"SELECT issued_count FROM task_ayuza.prelogin_limits WHERE ip_key=:key",
                       key=service.key('prelogin-ip',ip)).scalar_one()==30
    rejected(lambda:service.prelogin(ip=ip),429)
    # Reuse does not count as an issuance.
    first=next(r for r in results if r)
    refreshed=service.prelogin(ip=ip,token=first['token'])
    assert refreshed['session_id']==first['session_id']
    assert refreshed['csrf_token']!=first['csrf_token']

    uid,name,s=normal(service)
    with service.engine.connect() as c:
        before=one(c,"SELECT * FROM task_ayuza.sessions WHERE id=:id",id=s['session_id'])
    again=service.prelogin(ip=ip,token=s['token'])
    assert again['token']==s['token'] and again['session_id']==s['session_id']
    assert again['csrf_token']!=s['csrf_token']
    with service.engine.connect() as c:
        after=one(c,"SELECT * FROM task_ayuza.sessions WHERE id=:id",id=s['session_id'])
    assert before['expires_at']==after['expires_at']
    assert before['absolute_expires_at']==after['absolute_expires_at']
    rejected(lambda:service.renew(s['token'],s['csrf_token']),403)
    service.renew(s['token'],again['csrf_token'])


def test_limited_audit_bounded_and_cleanup(service):
    name='audit-'+uuid.uuid4().hex
    ip='198.51.100.221'
    for _ in range(5):service.reserve(name,ip,uuid.uuid4())
    for _ in range(50):
        rejected(lambda:service.reserve(name,ip,uuid.uuid4()),429)
    with service.engine.connect() as c:
        assert execute(c,"SELECT count(*) FROM task_ayuza.auth_limit_events WHERE key_kind='login' AND key_hash=:key",
                       key=service.key('login',name)).scalar_one()==1
    # A second key is independently recorded.
    for _ in range(5):service.reserve(name+'x',ip,uuid.uuid4())
    rejected(lambda:service.reserve(name+'x',ip,uuid.uuid4()),429)
    with create_engine(_test_url('TASK_AYUZA_TEST_MIGRATOR_URL'),hide_parameters=True).begin() as c:
        execute(c,"UPDATE task_ayuza.auth_limit_events SET last_event_at=last_event_at-interval '26 hours' WHERE key_hash=:key",
                key=service.key('login',name))
    service.cleanup()
    with service.engine.connect() as c:
        assert execute(c,"SELECT count(*) FROM task_ayuza.auth_limit_events WHERE key_kind='login' AND key_hash=:key",
                       key=service.key('login',name)).scalar_one()==0


def test_database_auth_constraints_and_runtime_limiter_permissions(service):
    from sqlalchemy.exc import IntegrityError
    uid,name,s=normal(service)
    with service.engine.connect() as c:
        with pytest.raises(IntegrityError) as e:
            execute(c,'UPDATE task_ayuza.sessions SET auth_version=NULL WHERE id=:id',id=s['session_id'])
        assert e.value.orig.sqlstate=='23514'
        c.rollback()
        with pytest.raises(DBAPIError) as e:
            execute(c,"UPDATE task_ayuza.login_attempts SET attempted_at=clock_timestamp()")
        assert e.value.orig.sqlstate=='42501'
        c.rollback()
        with pytest.raises(IntegrityError) as e:
            execute(c,"UPDATE task_ayuza.users SET login='MixedCase',login_normalized='MixedCase' WHERE id=:id",id=uid)
        assert e.value.orig.sqlstate=='23514'
        c.rollback()
