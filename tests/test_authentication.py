import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app
from app.security.authentication import COOKIE,csrf_token,token_hash,IDLE_SECONDS

PASSWORD='A long test-only passphrase 42!'
HEADERS={'X-APIShield-Action':'admin'}


@pytest.fixture
def login_app(tmp_path):
    settings=Settings(db_path=str(tmp_path/'auth.db'),start_gateway=False,admin_token='')
    with TestClient(create_app(settings),base_url='http://127.0.0.1:8002',client=('127.0.0.1',12345)) as client:
        yield client,client.app.state.runtime,settings


def setup(client,runtime):
    code=runtime.auth.setup_file.read_text().strip()
    response=client.post('/api/auth/setup',json=dict(username='Operator',password=PASSWORD,setup_code=code),headers=HEADERS)
    assert response.status_code==204,response.text
    return client.cookies.get(COOKIE)


def csrf_headers(client):
    return dict(HEADERS,**{'X-CSRF-Token':client.get('/api/session').json()['csrf_token']})


def test_no_automatic_token_or_data_access(login_app):
    client,runtime,_=login_app
    status=client.get('/api/session').json()
    assert status['setup_required'] and not status['authenticated']
    assert 'token' not in status and 'setup_code' not in status
    for path in ('services','settings','database','database/backup','traffic','events','audit','policies','metrics/system','discovery/history','stream'):
        response=client.post('/api/'+path,headers=HEADERS) if path=='database/backup' else client.get('/api/'+path)
        assert response.status_code==401,path
        assert response.headers['x-frame-options']=='DENY'
        assert response.headers['cache-control']=='no-store'


def test_first_account_requires_code_and_long_password(login_app):
    client,runtime,_=login_app
    body=dict(username='operator',password=PASSWORD,setup_code='wrong')
    assert client.post('/api/auth/setup',json=body,headers=HEADERS).status_code==401
    body['setup_code']=runtime.auth.setup_file.read_text().strip();body['password']='short'
    assert client.post('/api/auth/setup',json=body,headers=HEADERS).status_code==422
    body['password']=PASSWORD
    assert client.post('/api/auth/setup',json=body,headers=HEADERS).status_code==204
    assert client.post('/api/auth/setup',json=body,headers=HEADERS).status_code==409
    assert not runtime.auth.setup_file.exists() and not runtime.db.meta('admin_setup_hash')


def test_cookie_attributes_csrf_and_only_hashes_in_database(login_app):
    client,runtime,_=login_app
    token=setup(client,runtime)
    status=client.get('/api/session').json()
    assert status['authenticated'] and status['username']=='operator'
    assert status['csrf_token']==csrf_token(token)
    assert client.get('/api/services').status_code==200
    assert client.post('/api/auth/logout',headers=HEADERS).status_code==403
    assert client.post('/api/auth/logout',headers=dict(HEADERS,**{'X-CSRF-Token':'forged'})).status_code==403
    assert client.post('/api/auth/logout',headers=dict(csrf_headers(client),Origin='https://attacker.example')).status_code==403
    saved=json.dumps(runtime.db.query('SELECT * FROM admin_accounts')+runtime.db.query('SELECT * FROM admin_sessions'))
    assert PASSWORD not in saved and token not in saved and token_hash(token) in saved
    assert runtime.auth.account()['password_hash'].startswith('scrypt$131072$8$1$')
    response=client.post('/api/auth/logout',headers=csrf_headers(client))
    assert response.status_code==204 and 'HttpOnly' in response.headers['set-cookie'] and 'SameSite=strict' in response.headers['set-cookie']
    assert client.get('/api/services').status_code==401
    assert runtime.auth.session(token) is None


def test_login_generic_error_rotation_and_no_password_echo(login_app):
    client,runtime,_=login_app
    token=setup(client,runtime)
    for username in ('operator','unknown'):
        response=client.post('/api/auth/login',json=dict(username=username,password='wrong'),headers=HEADERS)
        assert response.status_code==401 and response.json()['error']['message']=='Invalid username or password'
    response=client.post('/api/auth/login',json=dict(username='OPERATOR',password=PASSWORD),headers=HEADERS)
    assert response.status_code==204
    assert 'HttpOnly' in response.headers['set-cookie'] and 'SameSite=strict' in response.headers['set-cookie'] and 'Path=/api' in response.headers['set-cookie']
    assert client.cookies.get(COOKIE)!=token and runtime.auth.session(token) is None
    response=client.post('/api/auth/login',json=dict(username='x',password=PASSWORD,extra='value'),headers=HEADERS)
    assert response.status_code==422 and PASSWORD not in response.text
    assert PASSWORD not in json.dumps(runtime.db.query('SELECT * FROM audit'))


def test_login_throttle_persists_and_has_retry_header(login_app,monkeypatch):
    client,runtime,_=login_app
    monkeypatch.setattr('app.security.authentication.password_matches',lambda *args:False)
    for _ in range(10):
        assert client.post('/api/auth/login',json=dict(username='operator',password='wrong'),headers=HEADERS).status_code==401
    response=client.post('/api/auth/login',json=dict(username='operator',password='wrong'),headers=HEADERS)
    assert response.status_code==429 and int(response.headers['retry-after'])>0
    assert runtime.db.query("SELECT * FROM rate_limits WHERE route='__admin_login'")


def test_absolute_expiry_and_idle_expiry(login_app):
    client,runtime,_=login_app
    token=setup(client,runtime)
    runtime.db.execute('UPDATE admin_sessions SET last_seen=?',(time.time()-IDLE_SECONDS-1,))
    assert client.get('/api/services').status_code==401
    assert runtime.auth.session(token) is None
    token=runtime.auth.issue('operator');client.cookies.set(COOKIE,token,path='/api',domain='127.0.0.1')
    runtime.db.execute('UPDATE admin_sessions SET expires_at=?',(time.time()-1,))
    assert client.get('/api/services').status_code==401


def test_password_change_revokes_every_session(login_app):
    client,runtime,_=login_app
    setup(client,runtime)
    second=runtime.auth.issue('operator')
    headers=csrf_headers(client)
    assert client.post('/api/auth/password',json=dict(current_password='incorrect',new_password='A different long test passphrase'),headers=headers).status_code==401
    assert client.post('/api/auth/password',json=dict(current_password=PASSWORD,new_password='A different long test passphrase'),headers=headers).status_code==204
    assert not runtime.db.query('SELECT * FROM admin_sessions') and runtime.auth.session(second) is None
    assert client.get('/api/services').status_code==401
    assert client.post('/api/auth/login',json=dict(username='operator',password=PASSWORD),headers=HEADERS).status_code==401
    assert client.post('/api/auth/login',json=dict(username='operator',password='A different long test passphrase'),headers=HEADERS).status_code==204


def test_credentials_and_session_survive_restart(login_app):
    client,runtime,settings=login_app
    token=setup(client,runtime)
    with TestClient(create_app(settings),base_url='http://127.0.0.1:8002',client=('127.0.0.1',12345)) as restarted:
        restarted.cookies.set(COOKIE,token,path='/api',domain='127.0.0.1')
        assert restarted.get('/api/services').status_code==200
        assert restarted.get('/api/session').json()['authenticated']
        assert not restarted.app.state.runtime.auth.setup_file.exists()


def test_remote_setup_and_cleartext_remote_admin_rejected(tmp_path):
    settings=Settings(db_path=str(tmp_path/'remote.db'),start_gateway=False,admin_token='')
    with TestClient(create_app(settings),base_url='http://127.0.0.1:8002',client=('192.168.1.20',1234)) as client:
        assert client.get('/api/session').status_code==403
        assert client.post('/api/auth/setup',json={},headers=HEADERS).status_code==403
    with TestClient(create_app(settings),base_url='https://127.0.0.1:8002',client=('192.168.1.20',1234)) as client:
        runtime=client.app.state.runtime
        response=client.post('/api/auth/setup',json=dict(username='operator',password=PASSWORD,setup_code=runtime.auth.setup_file.read_text().strip()),headers=HEADERS)
        assert response.status_code==403


def test_secure_cookie_on_https(login_app):
    _,runtime,settings=login_app
    with TestClient(create_app(settings),base_url='https://127.0.0.1:8002',client=('127.0.0.1',12345)) as client:
        code=runtime.auth.setup_file.read_text().strip()
        response=client.post('/api/auth/setup',json=dict(username='operator',password=PASSWORD,setup_code=code),headers=HEADERS)
        assert response.status_code==204 and 'Secure' in response.headers['set-cookie']
        assert 'max-age=' in response.headers['strict-transport-security']


def test_admin_cookie_and_csrf_never_forwarded_and_not_overwritten(upstream):
    _,gateway,runtime=upstream
    seen=[]
    def handler(request):
        seen.append(request)
        return httpx.Response(200,stream=httpx.ByteStream(b'ok'),headers=[('Set-Cookie',COOKIE+'=attacker; Path=/api'),('Set-Cookie','business=ok')])
    runtime.client._transport=httpx.MockTransport(handler)
    response=gateway.get('/student/health',headers={'Cookie':f'business=yes; {COOKIE}=private-session','X-CSRF-Token':'private-csrf'})
    assert response.status_code==200
    assert seen[0].headers['cookie']=='business=yes' and 'x-csrf-token' not in seen[0].headers
    assert response.headers.get_list('set-cookie')==['business=ok']


def test_reserved_secret_names_rejected(env):
    client,_,_=env
    assert client.put('/api/services/service-student/policy',json={'upstream_token_env':'APISHIELD_ADMIN_TOKEN'}).status_code==422


def test_authentication_request_bounds_and_fetch_metadata(login_app):
    client,_,_=login_app
    assert client.post('/api/auth/login',content='x'*65537,headers=HEADERS).status_code==413
    assert client.post('/api/auth/login',json={},headers={}).status_code==403
    assert client.get('/api/session',headers={'Sec-Fetch-Site':'cross-site'}).status_code==403
    assert client.get('/api/services',headers={'Host':'evil.example'}).status_code==400


def test_session_capacity_bound(login_app):
    _,runtime,_=login_app
    for _ in range(100):
        runtime.auth.issue('operator')
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as rejected:
        runtime.auth.issue('operator')
    assert rejected.value.status_code==429


def test_sql_filters_are_parameterized_and_files_are_private(env):
    client,_,runtime=env
    for route in ('traffic','events','discovery/ports'):
        response=client.get('/api/'+route,params={'q':"' OR 1=1; DROP TABLE services; --"})
        assert response.status_code==200
    assert len(runtime.db.services())==3
    for path in ('/data/sentinel.db','/data/admin-setup-code.txt','/runtime/processes.json','/static/%2e%2e/data/sentinel.db','/static/%2e%2e/data/admin-setup-code.txt'):
        assert client.get(path).status_code in (400,404)


async def test_stream_does_not_deliver_queued_event_after_revocation(env):
    from app.monitoring.collector import Collector
    collector=Collector(env[2].db)
    revoked=[False]
    async def disconnected(): return revoked[0]
    stream=collector.stream(disconnected)
    await anext(stream)
    collector.publish({'type':'private'})
    revoked[0]=True
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


def test_offline_owner_recovery_preserves_data(tmp_path,monkeypatch):
    from app.database.db import Database
    from scripts.reset_admin import reset_credentials
    monkeypatch.setattr('scripts.reset_admin.psutil.process_iter',lambda attrs:[])
    path=tmp_path/'recovery.db'
    db=Database(path)
    db.execute('INSERT INTO admin_accounts VALUES (1,?,?,?)',('operator','old-hash','time'))
    db.execute('INSERT INTO admin_sessions VALUES (?,?,?,?,?)',('token-hash','operator',1,1,9999999999))
    db.save_service('keep-api',{'name':'Keep this API'})
    db.event('keep-event','Keep this history')
    db.close()
    backup=reset_credentials(path)
    assert backup.exists()
    db=Database(path)
    assert not db.query('SELECT * FROM admin_accounts') and not db.query('SELECT * FROM admin_sessions')
    assert db.service('keep-api')['name']=='Keep this API'
    assert db.query('SELECT * FROM events')[0]['detail']=='Keep this history'
    assert db.query('SELECT * FROM audit')[0]['action']=='administrator_reset'
    db.close()


def test_offline_recovery_refuses_running_app(monkeypatch):
    from types import SimpleNamespace
    from scripts.reset_admin import ensure_stopped,ROOT
    monkeypatch.setattr('scripts.reset_admin.psutil.process_iter',lambda attrs:[SimpleNamespace(info={'cmdline':['python','-m','uvicorn','app.main:app'],'cwd':str(ROOT)})])
    with pytest.raises(RuntimeError,match='Stop APIShield first'):
        ensure_stopped()
