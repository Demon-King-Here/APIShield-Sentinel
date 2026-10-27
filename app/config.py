import os
import json
import ipaddress
import ssl
import psutil
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def resolve_interface_ip(interface):
    try:
        status = psutil.net_if_stats().get(interface)
        addresses = psutil.net_if_addrs().get(interface, [])
    except (psutil.Error,OSError):
        return None
    if not status or not status.isup:
        return None
    for entry in addresses:
        try:
            address = ipaddress.ip_address(entry.address)
        except ValueError:
            continue
        if address.version == 4 and address.is_private and not (address.is_loopback or address.is_link_local or address.is_unspecified or address.is_reserved):
            return str(address)
    return None


def gateway_selection():
    override = os.getenv('APISHIELD_GATEWAY_HOST')
    if override:
        return {'host': override}
    interface = os.getenv('APISHIELD_GATEWAY_INTERFACE')
    if interface:
        return {'interface': interface}
    path = ROOT / 'config/gateway.json'
    if not path.exists():
        return {'host': '127.0.0.1'}
    saved = json.loads(path.read_text(encoding='utf-8'))
    if set(saved) == {'interface'} and isinstance(saved['interface'], str) and 0 < len(saved['interface']) <= 128:
        return saved
    if set(saved) != {'host'}:
        raise ValueError('Save exactly one gateway interface name or host address')
    address = ipaddress.ip_address(saved['host'])
    if address.is_unspecified or address.is_link_local or not (address.is_loopback or address.is_private):
        raise ValueError('Saved gateway host must be one explicit loopback or private interface IP')
    return {'host': str(address)}


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: os.getenv('APISHIELD_DB', str(ROOT / 'data/sentinel.db')))
    admin_host: str = field(default_factory=lambda: os.getenv('APISHIELD_ADMIN_HOST', '127.0.0.1'))
    admin_port: int = field(default_factory=lambda: int(os.getenv('APISHIELD_ADMIN_PORT', '8002')))
    gateway_host: str | None = None
    gateway_interface: str | None = None
    gateway_port: int = field(default_factory=lambda: int(os.getenv('APISHIELD_GATEWAY_PORT', '8080')))
    admin_token: str = field(default_factory=lambda: os.getenv('APISHIELD_ADMIN_TOKEN', ''))
    upstream_hosts: set[str] = field(default_factory=lambda: set(os.getenv('APISHIELD_UPSTREAM_HOSTS', '127.0.0.1,::1').split(',')))
    gateway_certfile: str = field(default_factory=lambda: os.getenv('APISHIELD_GATEWAY_CERTFILE', ''))
    gateway_keyfile: str = field(default_factory=lambda: os.getenv('APISHIELD_GATEWAY_KEYFILE', ''))
    ca_file: str = field(default_factory=lambda: os.getenv('APISHIELD_CA_FILE', ''))
    start_gateway: bool = True
    retention: int = field(default_factory=lambda: int(os.getenv('APISHIELD_HISTORY_LIMIT','20000')))

    def __post_init__(self):
        path = Path(self.db_path).expanduser()
        self.db_path = str((path if path.is_absolute() else ROOT/path).resolve())
        if self.gateway_host is not None:
            return
        selected = {'interface':self.gateway_interface} if self.gateway_interface else gateway_selection()
        self.gateway_interface = selected.get('interface')
        self.gateway_host = resolve_interface_ip(self.gateway_interface) if self.gateway_interface else selected['host']

    def validate(self):
        import ipaddress
        if not 100 <= self.retention <= 1000000:
            raise ValueError('APISHIELD_HISTORY_LIMIT must be between 100 and 1000000')
        if self.admin_token and len(self.admin_token)<32:
            raise ValueError('Optional APISHIELD_ADMIN_TOKEN must contain at least 32 characters')
        if not ipaddress.ip_address(self.admin_host).is_loopback:
            raise ValueError('Remote management binding is unsupported; use a loopback address and an SSH/VPN tunnel')
        if any(not 1024 <= port <= 65535 for port in (self.admin_port, self.gateway_port)):
            raise ValueError('Listener ports must be between 1024 and 65535')
        if bool(self.gateway_certfile) != bool(self.gateway_keyfile):
            raise ValueError('Configure both APISHIELD_GATEWAY_CERTFILE and APISHIELD_GATEWAY_KEYFILE')
        if self.gateway_certfile:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(self.gateway_certfile, self.gateway_keyfile)
        if self.ca_file:
            ssl.create_default_context(cafile=self.ca_file)
        if self.gateway_host is not None:
            address = ipaddress.ip_address(self.gateway_host)
            if address.is_unspecified or address.is_link_local or not (address.is_loopback or address.is_private):
                raise ValueError('Gateway must bind one explicit loopback or private interface IP')
        network_gateway = self.gateway_interface or (self.gateway_host and not ipaddress.ip_address(self.gateway_host).is_loopback)
        if network_gateway and not self.gateway_certfile:
            raise ValueError('Network gateway access requires TLS certificate and key files; HTTP is allowed only on loopback')
        if self.admin_port == self.gateway_port:
            raise ValueError('Dashboard and gateway ports must differ')
        for host in self.upstream_hosts:
            address = ipaddress.ip_address(host)
            if not (address.is_loopback or address.is_private) or address.is_unspecified or address.is_link_local:
                raise ValueError('Upstream hosts must be explicit loopback or private IP addresses')
