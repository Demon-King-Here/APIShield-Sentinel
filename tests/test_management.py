import asyncio
import json
import httpx
import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app
from app.database.db import now
from app.monitoring.collector import Collector


def test_admin_access_host_origin(env):
    admin,_,_=env
    assert admin.get('/api/services',headers={'Authorization':''}).status_code==401
    assert admin.post('/api/discovery/scan',headers={'X-APIShield-Action':''}).status_code==403
    assert admin.get('/api/services',headers={'Host':'evil.example'}).status_code==400
    assert admin.post('/api/discovery/scan',headers={'Origin':'https://evil.example'}).status_code==403
    assert admin.get('/api/services',headers={'Origin':'null'}).status_code==403
    assert admin.get('/').status_code==200
    assert 'default-src' in admin.get('/').headers['content-security-policy']


def test_remote_admin_requires_token():
    with pytest.raises(ValueError):
        create_app(Settings(admin_host='0.0.0.0',admin_token=''))


def test_admin_validation_and_body_bound(env):
    admin,_,_=env
    assert admin.post('/api/services',content='bad json',headers={'Content-Type':'application/json'}).status_code==422
    assert admin.post('/api/services',content='x'*65537).status_code==413
    response=admin.post('/api/services',json={'name':'secrets','backend_url':'http://evil.test:5001','gateway_path':'/new'})
    assert response.status_code==422
    assert 'error' in response.json()


def test_service_crud_policy_and_persistence(env):
    admin,_,runtime=env
    config={'name':'Another API','backend_url':'http://127.0.0.1:5050','gateway_path':'/another'}
    response=admin.post('/api/services',json=config)
    assert response.status_code==201
    sid=response.json()['id']
    assert admin.post('/api/services',json=config).status_code==409
    config['name']='Renamed'
    assert admin.put('/api/services/'+sid,json=config).status_code==200
    assert admin.put('/api/services/'+sid+'/policy',json={'limit':4}).status_code==200
    assert runtime.db.service(sid)['policy']['limit']==4
    assert admin.delete('/api/services/'+sid).json()['backend_process_unchanged']
    assert admin.get('/api/services/'+sid).status_code==404
    assert len(admin.get('/api/audit').json())>=4


def test_mocked_scan(env,monkeypatch):
    admin,_,_=env
    from app.discovery.classification import classify
    def mock(services):
        row=classify({'port':5001,'local_address':'127.0.0.1','pid':123,'process':'python','executable':None,'windows_services':[]},services)
        return dict(timestamp=now(),source='Mock Windows',listeners=[row],success=True,limitations=[])
    monkeypatch.setattr('app.api.routes.scan',mock)
    response=admin.post('/api/discovery/scan')
    assert response.status_code==200
    rows=admin.get('/api/discovery/ports?port=5001').json()['listeners']
    assert rows[0]['pid']==123
    assert rows[0]['security_status']=='Needs Review'
    assert '5001' in admin.get('/api/discovery/ports?format=csv').text
    assert admin.get('/api/metrics/overview').json()['listening_ports']==1


def test_failed_scan_retains_snapshot(env,monkeypatch):
    admin,_,runtime=env
    runtime.db.execute('INSERT INTO listeners(data) VALUES (?)',(json.dumps({'port':5001,'local_address':'127.0.0.1'}),))
    monkeypatch.setattr('app.api.routes.scan',lambda s:dict(success=False,timestamp=now(),source='Permission denied',limitations=['Denied'],listeners=[]))
    assert not admin.post('/api/discovery/scan').json()['success']
    assert len(admin.get('/api/discovery/ports').json()['listeners'])==1


def test_verification_handling(upstream,monkeypatch):
    admin,_,runtime=upstream
    from app.discovery.classification import classify
    monkeypatch.setattr('app.security.verification.scan',lambda s:dict(success=True,listeners=[classify({'port':5001,'local_address':'127.0.0.1'},s)]))
    def handler(req):
        return httpx.Response(200,json={'status':'ok'},headers={'X-APIShield-Gateway':'Sentinel'} if req.url.port==8080 else {})
    runtime.client._transport=httpx.MockTransport(handler)
    report=admin.post('/api/services/service-student/verify').json()
    assert report['state']=='Gateway Managed'
    assert report['loopback_observed'] and report['forwarded']
    assert any(c['passed'] is None for c in report['checks'])
    assert admin.get('/api/services/service-student').json()['verification']['state']=='Gateway Managed'
    admin.put('/api/services/service-student/policy',json={'limit':3})
    assert admin.get('/api/services/service-student').json()['verification'] is None


def test_verification_failure(upstream,monkeypatch):
    admin,_,runtime=upstream
    monkeypatch.setattr('app.security.verification.scan',lambda s:dict(success=False,listeners=[]))
    runtime.client._transport=httpx.MockTransport(lambda req:httpx.Response(503))
    report=admin.post('/api/services/service-student/verify').json()
    assert report['state']=='Protection Failed' and not report['forwarded']


def test_monitoring_filters_aggregation_and_clear(upstream):
    admin,gateway,runtime=upstream
    gateway.get('/student/student')
    gateway.get('/student/student')
    assert admin.get('/api/metrics/overview').json()['total_requests']==2
    assert admin.get('/api/metrics/traffic').json()['apis'][0]['total']==2
    assert len(admin.get('/api/traffic?service_id=service-student&status=200').json())==2
    assert len(admin.get('/api/traffic?status=404').json())==0
    assert 'student' in admin.get('/api/traffic?format=csv').text
    assert admin.post('/api/history/clear').json()['configurations_preserved']
    assert admin.get('/api/metrics/overview').json()['total_requests']==0
    assert len(admin.get('/api/services').json())==3
    assert admin.get('/api/audit').json()[0]['action']=='history_cleared'


async def test_live_event_updates_bounded(env):
    runtime=env[2]
    collector=Collector(runtime.db)
    async def connected(): return False
    generator=collector.stream(connected)
    assert 'ready' in await anext(generator)
    collector.publish({'type':'request','data':{'status':200}})
    assert '200' in await anext(generator)
    for i in range(100): collector.publish({'sequence':i})
    assert next(iter(collector.subscribers)).qsize()==64
    await generator.aclose()
    assert not collector.subscribers


def test_restart_configuration(tmp_path):
    settings=Settings(db_path=str(tmp_path/'persist.db'),start_gateway=False)
    with TestClient(create_app(settings),base_url='http://127.0.0.1:8002') as client:
        runtime=client.app.state.runtime
        runtime.db.execute('DELETE FROM services WHERE id=?',('service-student',))
        runtime.db.meta('marker','preserved')
    with TestClient(create_app(settings),base_url='http://127.0.0.1:8002') as client:
        assert client.app.state.runtime.db.service('service-student') is None
        assert client.app.state.runtime.db.meta('marker')=='preserved'
