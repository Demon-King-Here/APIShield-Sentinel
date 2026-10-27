import json
import pytest
from types import SimpleNamespace
from app.config import Settings


def test_saved_gateway_interface_is_specific(tmp_path,monkeypatch):
    monkeypatch.setattr('app.config.ROOT',tmp_path)
    monkeypatch.delenv('APISHIELD_GATEWAY_HOST',raising=False)
    (tmp_path/'config').mkdir()
    (tmp_path/'config/gateway.json').write_text(json.dumps({'host':'172.20.10.5'}))
    settings=Settings()
    assert settings.gateway_host=='172.20.10.5'
    assert settings.admin_host=='127.0.0.1'
    monkeypatch.setenv('APISHIELD_GATEWAY_HOST','127.0.0.1')
    assert Settings().gateway_host=='127.0.0.1'


def test_saved_gateway_interface_rejects_wildcard(tmp_path,monkeypatch):
    monkeypatch.setattr('app.config.ROOT',tmp_path)
    monkeypatch.delenv('APISHIELD_GATEWAY_HOST',raising=False)
    (tmp_path/'config').mkdir()
    (tmp_path/'config/gateway.json').write_text(json.dumps({'host':'0.0.0.0'}))
    with pytest.raises(ValueError,match='explicit'):
        Settings()


def test_selected_adapter_resolves_current_address(tmp_path,monkeypatch):
    monkeypatch.setattr('app.config.ROOT',tmp_path)
    monkeypatch.delenv('APISHIELD_GATEWAY_HOST',raising=False)
    (tmp_path/'config').mkdir()
    (tmp_path/'config/gateway.json').write_text(json.dumps({'interface':'Wi-Fi'}))
    monkeypatch.setattr('app.config.psutil.net_if_stats',lambda:{'Wi-Fi':SimpleNamespace(isup=True)})
    addresses={'Wi-Fi':[SimpleNamespace(address='172.20.10.5')],'Other adapter':[SimpleNamespace(address='10.0.0.5')]}
    monkeypatch.setattr('app.config.psutil.net_if_addrs',lambda:addresses)
    settings=Settings()
    assert settings.gateway_interface=='Wi-Fi' and settings.gateway_host=='172.20.10.5'
    addresses['Wi-Fi']=[SimpleNamespace(address='192.168.1.42')]
    assert Settings().gateway_host=='192.168.1.42'
    addresses['Wi-Fi']=[SimpleNamespace(address='169.254.1.2')]
    assert Settings().gateway_host is None
    monkeypatch.setattr('app.config.psutil.net_if_stats',lambda:{'Wi-Fi':SimpleNamespace(isup=False)})
    assert Settings().gateway_host is None


async def test_running_gateway_follows_only_selected_adapter(env,monkeypatch):
    import asyncio
    from app.gateway.listener import GatewayListener
    runtime=env[2]
    runtime.settings.gateway_interface='Wi-Fi'
    address=['172.20.10.5']
    monkeypatch.setattr('app.gateway.listener.resolve_interface_ip',lambda interface:address[0] if interface=='Wi-Fi' else None)
    opened=[]
    class FakeSocket:
        def close(self): pass
    class FakeServer:
        started=False
        should_exit=False
        async def serve(self,sockets):
            self.started=True
            while not self.should_exit:
                await asyncio.sleep(.001)
    listener=GatewayListener(runtime)
    monkeypatch.setattr(listener,'open_socket',lambda host:(opened.append(host),FakeSocket())[1])
    monkeypatch.setattr(listener,'make_server',FakeServer)
    try:
        await listener.refresh()
        assert runtime.gateway_url=='http://172.20.10.5:8080' and runtime.gateway_healthy
        old_server=listener.server
        address[0]='192.168.1.42'
        await listener.refresh()
        assert old_server.should_exit
        assert runtime.gateway_url=='http://192.168.1.42:8080'
        address[0]=None
        await listener.refresh()
        assert runtime.gateway_url is None and not runtime.gateway_healthy
        assert runtime.gateway_state=='waiting_for_interface'
        address[0]='10.0.0.42'
        await listener.refresh()
        assert runtime.gateway_url=='http://10.0.0.42:8080'
        assert opened==['172.20.10.5','192.168.1.42','10.0.0.42']
    finally:
        await listener.close()


async def test_busy_gateway_port_keeps_management_runtime_alive(env,monkeypatch):
    from app.gateway.listener import GatewayListener
    runtime=env[2]
    runtime.settings.gateway_interface=None
    runtime.settings.gateway_host='127.0.0.1'
    listener=GatewayListener(runtime)
    def fail(host): raise OSError('occupied')
    monkeypatch.setattr(listener,'open_socket',fail)
    await listener.refresh()
    assert runtime.gateway_url is None and runtime.gateway_state=='unavailable'
    assert runtime.db.services()
    await listener.close()


def test_management_stays_available_when_adapter_has_no_ip(env):
    admin,_,runtime=env
    runtime.set_gateway_host(None)
    runtime.gateway_state='waiting_for_interface'
    health=admin.get('/api/health').json()
    assert health['status']=='ok' and not health['gateway']
    assert admin.get('/api/settings').json()['gateway_url'] is None
    assert admin.post('/api/services/service-student/verify').status_code==503
