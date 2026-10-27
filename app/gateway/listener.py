"""Follow one selected adapter without opening any other network interface."""
import asyncio
import socket
from contextlib import nullcontext
import uvicorn
from app.config import resolve_interface_ip


class GatewayListener:
    def __init__(self, runtime):
        self.runtime = runtime
        self.fixed_host = runtime.settings.gateway_host
        self.server = None
        self.task = None
        self.sock = None
        self.bound_host = None
        self.last_notice = None
        self.closed = asyncio.Event()

    def notice(self, state, detail):
        self.runtime.gateway_state = state
        if (state,detail) != self.last_notice:
            self.last_notice = (state,detail)
            self.runtime.db.event('gateway_binding_changed',detail,'info' if state=='ready' else 'warning')
            self.runtime.db.audit('gateway_binding_changed',detail)
            self.runtime.collector.publish({'type':'gateway_binding','state':state})

    def open_socket(self, host):
        sock = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,socket.SOCK_STREAM)
        try:
            # Never share a Windows listener with an unrelated process.
            if hasattr(socket,'SO_EXCLUSIVEADDRUSE'):
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
            else:
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            sock.bind((host,self.runtime.settings.gateway_port))
            sock.listen(128)
            sock.setblocking(False)
            return sock
        except BaseException:
            sock.close()
            raise

    def make_server(self):
        server = uvicorn.Server(uvicorn.Config(self.runtime.gateway_app,host=self.bound_host,port=self.runtime.settings.gateway_port,
            log_level='warning',access_log=False,proxy_headers=False,server_header=False,
            ssl_certfile=self.runtime.settings.gateway_certfile or None,
            ssl_keyfile=self.runtime.settings.gateway_keyfile or None,
            limit_concurrency=150,timeout_keep_alive=5,timeout_graceful_shutdown=3))
        server.capture_signals = nullcontext
        return server

    async def stop_listener(self):
        self.runtime.gateway_healthy = False
        self.runtime.set_gateway_host(None)
        if self.server:
            self.server.should_exit = True
        if self.task:
            try:
                await asyncio.wait_for(self.task,timeout=8)
            except (TimeoutError,asyncio.CancelledError):
                self.task.cancel()
                await asyncio.gather(self.task,return_exceptions=True)
            except Exception:
                pass
        if self.sock:
            self.sock.close()
        self.server = self.task = self.sock = None
        self.bound_host = None

    async def refresh(self):
        interface = self.runtime.settings.gateway_interface
        try:
            target = resolve_interface_ip(interface) if interface else self.fixed_host
        except (OSError,ValueError):
            target = None
        if target == self.bound_host and self.task and not self.task.done():
            return
        if self.task:
            await self.stop_listener()
        if target is None:
            self.runtime.set_gateway_host(None)
            self.notice('waiting_for_interface',f'Gateway paused: selected adapter {interface} has no active private IPv4 address.')
            return
        try:
            self.sock = self.open_socket(target)
            self.bound_host = target
            self.server = self.make_server()
            self.task = asyncio.create_task(self.server.serve(sockets=[self.sock]))
            for _ in range(100):
                if self.server.started or self.task.done():
                    break
                await asyncio.sleep(.05)
            if not self.server.started or self.task.done():
                raise RuntimeError('Gateway listener did not start')
            self.runtime.set_gateway_host(target)
            self.runtime.gateway_healthy = True
            self.notice('ready',f'Gateway listening on {target}:{self.runtime.settings.gateway_port}'+(f' on selected adapter {interface}.' if interface else '.'))
        except (OSError,RuntimeError):
            await self.stop_listener()
            self.notice('unavailable',f'Gateway cannot bind {target}:{self.runtime.settings.gateway_port}; check the selected address and occupied ports. Retrying.')

    async def watch(self):
        while not self.closed.is_set():
            try:
                await asyncio.wait_for(self.closed.wait(),timeout=3)
            except asyncio.TimeoutError:
                await self.refresh()

    async def close(self):
        self.closed.set()
        await self.stop_listener()
