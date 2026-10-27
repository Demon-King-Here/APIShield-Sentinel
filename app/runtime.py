import asyncio
import secrets
import ssl
import httpx
from app.database.db import Database
from app.gateway.rate_limiter import RateLimiter
from app.gateway.proxy import create_gateway
from app.monitoring.collector import Collector
from app.security.authentication import Authentication


class Runtime:
    def __init__(self, settings):
        self.settings = settings
        self.db = Database(settings.db_path, settings.retention)
        self.limiter = RateLimiter(db=self.db)
        self.monitor_task = None
        self.collector = Collector(self.db)
        trust = ssl.create_default_context(cafile=settings.ca_file or None)
        self.client = httpx.AsyncClient(trust_env=False, verify=trust, follow_redirects=False, timeout=10,
                                       limits=httpx.Limits(max_connections=100,max_keepalive_connections=20))
        self.auth = Authentication(self)
        self.internal_secret = secrets.token_urlsafe(48)
        self.gateway_healthy = False
        self.gateway_state = 'starting'
        self.scan_lock = asyncio.Lock()
        self.set_gateway_host(settings.gateway_host)
        self.gateway_app = create_gateway(self)

    def set_gateway_host(self, host):
        self.settings.gateway_host = host
        address = {'0.0.0.0':'127.0.0.1','::':'::1'}.get(host,host)
        scheme = 'https' if self.settings.gateway_certfile else 'http'
        self.gateway_url = None if address is None else f'{scheme}://[{address}]:{self.settings.gateway_port}' if ':' in address else f'{scheme}://{address}:{self.settings.gateway_port}'
        self.db.meta('runtime_configuration',dict(admin_host=self.settings.admin_host,admin_port=self.settings.admin_port,
            gateway_host=host,gateway_interface=self.settings.gateway_interface,gateway_port=self.settings.gateway_port))

    def start_monitoring(self):
        async def sample():
            while True:
                self.db.save_system_sample(self.collector.overview())
                await asyncio.sleep(10)
        self.monitor_task=asyncio.create_task(sample())

    async def close(self):
        if self.monitor_task:
            self.monitor_task.cancel()
            await asyncio.gather(self.monitor_task,return_exceptions=True)
        await self.client.aclose()
        self.db.close()
