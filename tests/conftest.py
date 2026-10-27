import httpx
import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from app.config import Settings
from app.database.models import ServiceInput
from app.main import create_app
from app.gateway.proxy import create_gateway

Path('test-results').mkdir(exist_ok=True)


@pytest.fixture
def env(tmp_path):
    settings = Settings(db_path=str(tmp_path/'sentinel.db'),start_gateway=False,admin_token='test-automation-token-with-32-characters')
    with TestClient(create_app(settings),base_url='http://127.0.0.1:8002',client=('127.0.0.1',12345)) as admin:
        runtime = admin.app.state.runtime
        for sid,name,port,prefix in [('service-student','Student',5001,'/student'),('service-inventory','Inventory',5002,'/inventory'),('service-auth','Authentication',5003,'/auth')]:
            runtime.db.save_service(sid,ServiceInput(name=name,backend_url=f'http://127.0.0.1:{port}',gateway_path=prefix).model_dump())
        token = settings.admin_token
        admin.headers.update({'Authorization':f'Bearer {token}','X-APIShield-Action':'admin'})
        with TestClient(create_gateway(runtime)) as gateway:
            yield admin,gateway,runtime


@pytest.fixture
def upstream(env):
    admin,gateway,runtime = env
    async def handler(request):
        return httpx.Response(201 if request.method=='POST' else 200,
                              stream=httpx.ByteStream(json.dumps({'method':request.method,'path':request.url.path,'query':request.url.query.decode(),'body':request.content.decode(),'header':request.headers.get('x-test'),'forwarded':request.headers.get('x-forwarded-for'),'authorization':request.headers.get('authorization'),'cookie':request.headers.get('cookie')}).encode()),
                              headers=[('X-Upstream','yes'),('Connection','x-remove'),('X-Remove','secret'),('Set-Cookie','a=1'),('Set-Cookie','b=2')])
    # Run closure on the TestClient loop so no live HTTP pool leaks.
    env[0].portal.call(runtime.client.aclose)
    runtime.client = httpx.AsyncClient(transport=httpx.MockTransport(handler),follow_redirects=False)
    return env
