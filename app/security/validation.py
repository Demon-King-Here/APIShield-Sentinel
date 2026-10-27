import ipaddress
from urllib.parse import urlsplit, unquote


def validate_backend(url, settings):
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError('Whitespace and control characters are forbidden in backend origins')
    try:
        parsed = urlsplit(url)
        address = ipaddress.ip_address(parsed.hostname or '')
        port = parsed.port
    except ValueError:
        raise ValueError('Backend must use an allowed literal IP address and explicit port') from None
    if parsed.scheme not in {'http','https'} or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/'):
        raise ValueError('Backend must be an HTTP(S) origin without credentials, path, query, or fragment')
    if str(address) not in settings.upstream_hosts or not port or port < 1024 or port in {settings.admin_port, settings.gateway_port}:
        raise ValueError('Backend IP or port is not permitted; management/gateway loops are forbidden')
    return url.rstrip('/')


def safe_request_path(raw):
    path = raw.split(b'?', 1)[0].decode('ascii', errors='replace') if isinstance(raw, bytes) else raw
    for _ in range(5):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if any(c in path for c in ('%','\\','?','#')) or '//' in path or any(ord(c) < 32 or ord(c) == 127 for c in path) or any(p in ('.','..') for p in path.split('/')):
        raise ValueError('Ambiguous or unsafe path')
    return path


def path_matches(path, prefix):
    return prefix == '/' or path == prefix or path.startswith(prefix.rstrip('/') + '/')
