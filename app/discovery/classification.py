import ipaddress
from urllib.parse import urlsplit


def classify(listener, services):
    address = ipaddress.ip_address(listener['local_address'].split('%')[0])
    matches = []
    for service in services:
        parsed = urlsplit(service['backend_url'])
        if parsed.port == listener['port'] and (address.is_unspecified or str(address) == parsed.hostname):
            matches.append(service)
    enabled = [s for s in matches if s['enabled']]
    failed = any(s.get('verification') and s['verification'].get('state')=='Protection Failed' for s in enabled)
    verified = any(s.get('verification') and s['verification'].get('forwarded') and s['verification'].get('state')!='Protection Failed' for s in enabled)
    managed = verified or any(s.get('forwarded_observed') for s in enabled)
    critical = listener['port'] in {22,53,88,135,139,389,445,636,3389,5985,5986} and not matches
    return dict(listener, classification='Known configured API' if matches else 'Unknown',
        reachability='Unknown', binding_scope='Loopback' if address.is_loopback else 'Network interface',
        gateway_status='Routed' if enabled else 'Unrouted',
        security_status='Needs Review' if critical else 'Potentially Exposed' if not address.is_loopback else 'Protection Failed' if failed else 'Gateway Managed' if managed else 'Needs Review',
        explanation=('Potential infrastructure service: review its purpose and access controls manually. No configuration changes were made. External reachability is unknown.' if critical else
                     'Latest verification failed; inspect its check results in API Inventory. A loopback binding alone does not verify the intended policy.' if failed and address.is_loopback else
                     'Gateway forwarding observed for the current configuration; loopback listener observed. Other local processes can still connect. External reachability not tested.' if managed and address.is_loopback else
                     'Gateway route configured, but no current forwarding evidence or successful verification is available. Use Verify or send a request through the gateway. Other local processes can still connect.' if enabled and address.is_loopback else
                     'Network interface binding observed. Direct network access may be possible; no external probe has confirmed reachability. Bind backend to loopback or enforce access separately.' if not address.is_loopback else
                     'Loopback socket observed. Protocol and security policy have not been established.'),
        service_ids=[s['id'] for s in matches])
