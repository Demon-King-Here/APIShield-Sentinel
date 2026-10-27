"""Regression tests for public-install defaults, TLS and feature boundaries."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
from types import SimpleNamespace
import httpx
import pytest
from fastapi.testclient import TestClient
from app.api.routes import ready
from app.config import ROOT, Settings
from app.gateway.listener import GatewayListener
from app.main import create_app
from app.runtime import Runtime


@pytest.fixture
def clean_environment(monkeypatch):
    for name in list(os.environ):
        if name.startswith('APISHIELD_'):
            monkeypatch.delenv(name)


@pytest.fixture
def certificate(tmp_path):
    executable = shutil.which('openssl')
    if not executable and os.name == 'nt':
        candidate = Path(r'C:\Program Files\Git\usr\bin\openssl.exe')
        executable = str(candidate) if candidate.is_file() else None
    if not executable:
        pytest.skip('OpenSSL is needed to generate the temporary TLS fixture')
    cert, key = tmp_path/'gateway.pem', tmp_path/'gateway.key'
    subprocess.run([executable, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'],
                   check=True, capture_output=True, timeout=30)
    return cert, key


def test_fresh_install_has_empty_inventory_and_no_traffic_generator(tmp_path, clean_environment):
    settings = Settings(db_path=str(tmp_path/'clean.db'), start_gateway=False,
                        admin_token='test-only-automation-token-over-32-characters')
    assert settings.gateway_host == '127.0.0.1'
    with TestClient(create_app(settings), base_url='http://127.0.0.1:8002',
                    client=('127.0.0.1',1234)) as client:
        client.headers.update({'Authorization':'Bearer '+settings.admin_token,'X-APIShield-Action':'admin'})
        assert client.get('/api/services').json() == []
        assert client.post('/api/load-test/start',json={'service_id':'service-student','confirmed':True}).status_code == 404
        assert client.get('/api/load-test').status_code == 404
        assert client.get('/api/load-test/missing').status_code == 404
        assert client.post('/api/load-test/missing/stop').status_code == 404
        # No gateway is started by this fixture. Do not probe a developer's real
        # process that may already own the default gateway port.
        client.app.state.runtime.set_gateway_host(None)
        assert client.get('/api/ready').status_code == 503


def test_network_gateway_requires_tls_even_when_adapter_is_disconnected(clean_environment, monkeypatch):
    with pytest.raises(ValueError, match='requires TLS'):
        Settings(gateway_host='192.168.1.10').validate()
    monkeypatch.setattr('app.config.resolve_interface_ip',lambda _:None)
    with pytest.raises(ValueError, match='requires TLS'):
        Settings(gateway_interface='Disconnected').validate()


@pytest.mark.parametrize('kwargs',[
    {'gateway_host':'0.0.0.0'}, {'gateway_host':'169.254.1.2'},
    {'gateway_host':'8.8.8.8'}, {'admin_host':'0.0.0.0','admin_token':'x'*32},
    {'admin_port':0}, {'gateway_port':70000}, {'gateway_keyfile':'missing.key'},
])
def test_unsafe_or_incomplete_config_is_rejected(kwargs, clean_environment):
    with pytest.raises(ValueError):
        Settings(**kwargs).validate()


def test_adapter_environment_selection(clean_environment, monkeypatch):
    monkeypatch.setenv('APISHIELD_GATEWAY_INTERFACE','Ethernet')
    monkeypatch.setattr('app.config.resolve_interface_ip',lambda _: '192.168.1.10')
    assert Settings().gateway_host == '192.168.1.10'
    monkeypatch.setenv('APISHIELD_GATEWAY_HOST','127.0.0.1')
    assert Settings().gateway_interface is None


def test_config_check_opens_no_database(tmp_path, clean_environment):
    database = tmp_path/'not-created.db'
    environment = dict(os.environ, APISHIELD_DB=str(database))
    result = subprocess.run([sys.executable,'-m','app','--check-config'],cwd=ROOT,
                            env=environment,capture_output=True,text=True,timeout=15)
    assert result.returncode == 0, result.stderr
    assert 'Configuration valid' in result.stdout
    assert not database.exists()


async def test_real_tls_listener_and_verified_readiness(tmp_path, certificate, clean_environment):
    cert, key = certificate
    with socket.socket() as candidate:
        candidate.bind(('127.0.0.1',0))
        port = candidate.getsockname()[1]
    settings = Settings(db_path=str(tmp_path/'tls.db'),gateway_host='127.0.0.1',
                        gateway_port=port,gateway_certfile=str(cert),gateway_keyfile=str(key),ca_file=str(cert))
    settings.validate()
    runtime = Runtime(settings)
    listener = GatewayListener(runtime)
    try:
        await listener.refresh()
        assert runtime.gateway_healthy
        assert runtime.gateway_url == f'https://127.0.0.1:{port}'
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(runtime=runtime)))
        assert (await ready(request)).status_code == 200
        async with httpx.AsyncClient(trust_env=False) as untrusted:
            with pytest.raises(httpx.ConnectError):
                await untrusted.get(runtime.gateway_url+'/_sentinel/health')
        response = await runtime.client.get(runtime.gateway_url+'/unregistered')
        assert response.status_code == 404
        assert 'server' not in response.headers
    finally:
        await listener.close()
        await runtime.close()
