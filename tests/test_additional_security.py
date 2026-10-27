import asyncio
import json
import time
import httpx
import pytest
from app.config import Settings
from app.security.validation import validate_backend
from app.gateway.rate_limiter import RateLimiter


def test_reject_backend_whitespace():
    with pytest.raises(ValueError):
        validate_backend('http://127.0.0.1:5001\n',Settings())


def test_rate_window_expires(monkeypatch):
    clock=[0.0]
    monkeypatch.setattr('app.gateway.rate_limiter.time.monotonic',lambda:clock[0])
    limiter=RateLimiter()
    assert limiter.check('route','client',1,2)[0]
    assert not limiter.check('route','client',1,2)[0]
    clock[0]=2.1
    assert limiter.check('route','client',1,2)[0]


def test_config_change_invalidates_forwarding_evidence(upstream):
    admin,gateway,_=upstream
    assert admin.get('/api/metrics/overview').json()['gateway_managed']==0
    gateway.get('/student/student')
    assert admin.get('/api/metrics/overview').json()['gateway_managed']==1
    assert admin.get('/api/services').json()[0]['security_state']=='Gateway Managed'
    admin.put('/api/services/service-student/policy',json={'limit':8})
    assert admin.get('/api/metrics/overview').json()['gateway_managed']==0
    assert admin.get('/api/services').json()[0]['security_state']=='Needs Review'


def test_total_deadline(upstream):
    admin,gateway,runtime=upstream
    config=admin.get('/api/services/service-student').json()
    config.pop('id');config.pop('verification');config['timeout']=.1
    admin.put('/api/services/service-student',json=config)
    async def slow(req):
        await asyncio.sleep(.3)
        return httpx.Response(200,stream=httpx.ByteStream(b'ok'))
    runtime.client._transport=httpx.MockTransport(slow)
    began=time.monotonic()
    response=gateway.get('/student/student')
    assert response.status_code==502 and response.json()['error']['code']=='backend_timeout'
    assert time.monotonic()-began < 1


def test_redirect_not_followed(upstream):
    _,gateway,runtime=upstream
    calls=[]
    def redirect(req):
        calls.append(str(req.url))
        return httpx.Response(302,headers={'Location':'http://169.254.169.254/'},stream=httpx.ByteStream(b''))
    runtime.client._transport=httpx.MockTransport(redirect)
    response=gateway.get('/student/student',follow_redirects=False)
    assert response.status_code==302 and len(calls)==1


def test_critical_listener_requires_review():
    from app.discovery.classification import classify
    result=classify({'local_address':'0.0.0.0','port':445},[])
    assert result['security_status']=='Needs Review'
    assert result['classification']=='Unknown'


def test_retention_without_requests(env):
    runtime=env[2]
    runtime.db.retention=2
    for i in range(5):
        runtime.db.event('port_discovered',str(i))
        runtime.db.audit('scan',str(i))
    assert len(runtime.db.query('SELECT * FROM events'))==2
    assert len(runtime.db.query('SELECT * FROM audit'))==2


def test_changed_allowlist_rejects_persisted_origins(upstream):
    admin,gateway,runtime=upstream
    runtime.settings.upstream_hosts.clear()
    response=gateway.get('/student/student')
    assert response.status_code==503
    assert response.json()['error']['code']=='upstream_configuration_rejected'
    assert admin.post('/api/services/service-student/verify').status_code==422


def test_verification_cannot_overwrite_new_configuration(upstream,monkeypatch):
    admin,_,runtime=upstream
    runtime.client._transport=httpx.MockTransport(lambda req:httpx.Response(200,headers={'X-APIShield-Gateway':'Sentinel'}))
    def change_during_scan(services):
        config=runtime.db.service('service-student')
        config.pop('id');config.pop('verification')
        config['policy']['limit']=5
        runtime.db.save_service('service-student',config)
        return {'success':True,'listeners':[]}
    monkeypatch.setattr('app.security.verification.scan',change_during_scan)
    response=admin.post('/api/services/service-student/verify').json()
    assert response['state']=='Protection Failed'
    assert 'changed' in response['explanation']
    assert runtime.db.service('service-student')['verification'] is None
