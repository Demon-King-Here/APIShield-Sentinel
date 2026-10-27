import asyncio
import gzip
import httpx
import pytest


def test_get_forwarding_query_headers_response(upstream):
    admin,gateway,runtime=upstream
    response=gateway.get('/student/student?search=hello%20world&tag=a&tag=b',headers={'X-Test':'present','X-Forwarded-For':'8.8.8.8','Connection':'x-secret','X-Secret':'never'})
    assert response.status_code==200
    data=response.json()
    assert data['method']=='GET' and data['path']=='/student'
    assert data['query']=='search=hello%20world&tag=a&tag=b'
    assert data['header']=='present' and data['forwarded'] is None
    assert response.headers['x-upstream']=='yes' and 'x-remove' not in response.headers
    assert len(response.headers.get_list('set-cookie'))==2
    assert response.headers['x-apishield-gateway']=='Sentinel'
    assert admin.get('/api/metrics/overview').json()['total_requests']==1


def test_post_forwarding(upstream):
    _,gateway,_=upstream
    response=gateway.post('/auth/auth/login',content=b'{"username":"test-user","password":"example"}',headers={'Content-Type':'application/json','Authorization':'Bearer example'})
    assert response.status_code==201
    assert response.json()['body']=='{"username":"test-user","password":"example"}'
    assert response.json()['authorization']=='Bearer example'


def test_unknown_route(upstream):
    _,gateway,_=upstream
    assert gateway.get('/students/student').status_code==404
    assert gateway.get('/api/services').status_code==404


def test_unsafe_path(upstream):
    _,gateway,_=upstream
    assert gateway.get('/student/%252e%252e/api').status_code==400
    assert gateway.get('/student/a%5cb').status_code==400


def test_disabled_route(upstream):
    admin,gateway,_=upstream
    config=admin.get('/api/services/service-student').json()
    config.pop('id');config.pop('verification');config['enabled']=False
    assert admin.put('/api/services/service-student',json=config).status_code==200
    assert gateway.get('/student/student').status_code==404


def test_rate_limit_and_untrusted_identity(upstream):
    admin,gateway,_=upstream
    assert admin.put('/api/services/service-student/policy',json={'limit':2,'window':60}).status_code==200
    assert gateway.get('/student/student').status_code==200
    assert gateway.get('/student/student').status_code==200
    blocked=gateway.get('/student/student',headers={'X-Forwarded-For':'new-client'})
    assert blocked.status_code==429 and int(blocked.headers['retry-after'])>0
    events=admin.get('/api/events?type=rate_limit_exceeded').json()
    assert len(events)==1
    assert admin.get('/api/metrics/overview').json()['blocked']==1


def test_policy_methods_paths_and_auth(upstream,monkeypatch):
    admin,gateway,_=upstream
    monkeypatch.setenv('TEST_CLIENT_KEY','a-secure-example')
    admin.put('/api/services/service-student/policy',json={'methods':['GET'],'allowed_paths':['/student/student'],'client_key_env':'TEST_CLIENT_KEY'})
    assert gateway.post('/student/student').status_code==405
    assert gateway.get('/student/health').status_code==403
    assert gateway.get('/student/student').status_code==401
    assert gateway.get('/student/student',headers={'X-API-Key':'a-secure-example'}).status_code==200
    monkeypatch.delenv('TEST_CLIENT_KEY')
    assert gateway.get('/student/student',headers={'X-API-Key':'a-secure-example'}).status_code==401


def test_upstream_env_credentials(upstream,monkeypatch):
    admin,gateway,_=upstream
    admin.put('/api/services/service-student/policy',json={'upstream_token_env':'TEST_UPSTREAM_TOKEN'})
    assert gateway.get('/student/student').status_code==503
    monkeypatch.setenv('TEST_UPSTREAM_TOKEN','secret-value')
    response=gateway.get('/student/student',headers={'Authorization':'Bearer hostile'})
    assert response.json()['authorization']=='Bearer secret-value'
    assert 'secret-value' not in admin.get('/api/traffic').text
    assert 'secret-value' not in admin.get('/api/events').text


def test_body_size_known_and_streamed(upstream):
    admin,gateway,_=upstream
    admin.put('/api/services/service-student/policy',json={'max_body':3})
    assert gateway.post('/student/student',content=b'abcd').status_code==413
    assert gateway.post('/student/student',content=iter([b'ab',b'cd'])).status_code==413
    assert gateway.post('/student/student',content=b'abc').status_code==201


@pytest.mark.parametrize('exception,category',[(httpx.ConnectError,'backend_unavailable'),(httpx.ReadTimeout,'backend_timeout')])
def test_backend_failures(upstream,exception,category):
    _,gateway,runtime=upstream
    def fail(request):
        raise exception('internal sensitive trace')
    runtime.client._transport=httpx.MockTransport(fail)
    response=gateway.get('/student/student')
    assert response.status_code==502 and response.json()['error']['code']==category
    assert 'sensitive' not in response.text


def test_response_limit(upstream):
    _,gateway,runtime=upstream
    runtime.client._transport=httpx.MockTransport(lambda req:httpx.Response(200,stream=httpx.ByteStream(b'x'*(8*1024*1024+1))))
    response=gateway.get('/student/student')
    assert response.status_code==502
    assert response.json()['error']['code']=='upstream_response_too_large'


def test_response_compression(upstream):
    _,gateway,runtime=upstream
    runtime.client._transport=httpx.MockTransport(lambda req:httpx.Response(200,stream=httpx.ByteStream(gzip.compress(b'test data')),headers={'Content-Encoding':'gzip'}))
    response=gateway.get('/student/student')
    assert response.content==b'test data'


def test_strip_or_preserve_prefix(upstream):
    admin,gateway,_=upstream
    config=admin.get('/api/services/service-student').json()
    config.pop('id');config.pop('verification');config['strip_prefix']=False
    admin.put('/api/services/service-student',json=config)
    assert gateway.get('/student/student').json()['path']=='/student/student'


def test_logging_redacts_query_and_body(upstream):
    admin,gateway,_=upstream
    gateway.post('/auth/auth/login?token=secret-query',content='secret-password',headers={'Authorization':'Bearer secret-bearer','Cookie':'secret-cookie'})
    history=admin.get('/api/traffic').text+admin.get('/api/events').text
    assert all(v not in history for v in ['secret-query','secret-password','secret-bearer','secret-cookie'])


def test_shared_upstream_pool_does_not_leak_cookies(upstream):
    _,gateway,_=upstream
    gateway.get('/student/student')
    response=gateway.get('/student/student')
    # TestClient has its own browser cookie jar, so use a different backend route.
    response=gateway.get('/inventory/inventory',headers={'Cookie':''})
    assert response.json()['cookie'] in (None,'')
