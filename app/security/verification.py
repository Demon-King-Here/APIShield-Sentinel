import asyncio
import json
import os
import httpx
from urllib.parse import urlsplit
from app.database.db import now
from app.discovery.windows_scanner import scan
from app.gateway.proxy import upstream_stream


async def probe(runtime, url, headers, timeout):
    async with asyncio.timeout(timeout):
        async with upstream_stream(runtime.client, 'GET', url, b'', list(headers.items()), timeout) as response:
            return response.status_code, response.headers.get('x-apishield-gateway')


async def verify(runtime, service):
    revision = runtime.db.meta('service_revision:'+service['id'])
    checks = []
    healthy = False
    forwarded = False
    headers = {'X-APIShield-Internal':runtime.internal_secret}
    key_name = service['policy']['client_key_env']
    if key_name:
        headers['X-API-Key'] = os.getenv(key_name,'')
    try:
        upstream_env = service['policy']['upstream_token_env']
        upstream_headers = {'Authorization':'Bearer '+os.getenv(upstream_env,'')} if upstream_env else {}
        health_status, _ = await probe(runtime,service['backend_url']+service['health_path'],upstream_headers,service['timeout'])
        healthy = 200 <= health_status < 300
        checks.append({'check':'Backend health','passed':healthy,'detail':f'HTTP {health_status} from configured health path'})
    except (httpx.HTTPError, TimeoutError):
        checks.append({'check':'Backend health','passed':False,'detail':'Backend unavailable or timed out'})
    gateway_path = service['gateway_path'] + service['verification_path'] if service['strip_prefix'] else service['verification_path']
    try:
        status, marker = await probe(runtime,runtime.gateway_url+gateway_path,headers,service['timeout']+1)
        forwarded = 200 <= status < 300 and marker == 'Sentinel'
        checks.append({'check':'Gateway forwarding','passed':forwarded,'detail':f'HTTP {status}; enabled route must return upstream success'})
        if key_name:
            rejected, _ = await probe(runtime,runtime.gateway_url+gateway_path,{},service['timeout'])
            checks.append({'check':'Gateway authentication','passed':rejected==401,'detail':f'Request without key returned HTTP {rejected}'})
    except (httpx.HTTPError, TimeoutError):
        checks.append({'check':'Gateway forwarding','passed':False,'detail':'Gateway unavailable or timed out'})
    snapshot = await asyncio.to_thread(scan, runtime.db.services())
    port = urlsplit(service['backend_url']).port
    listeners = [r for r in snapshot['listeners'] if r['port']==port]
    loopback = bool(listeners) and all(r['binding_scope']=='Loopback' for r in listeners)
    checks.append({'check':'Loopback-only listeners on backend port','passed':loopback if snapshot['success'] and listeners else None,
                   'detail':f'{len(listeners)} listener(s) observed. ' + ('Only loopback bindings observed.' if loopback else 'Binding evidence incomplete or network listener present.')})
    checks.append({'check':'External direct-access restriction','passed':None,'detail':'No independent remote probe performed. Local processes can bypass the gateway. Other forwarding mechanisms are outside this scan.'})
    success = healthy and forwarded and all(c['passed'] is not False for c in checks[:2 + int(bool(key_name))])
    state = 'Gateway Managed' if success else 'Protection Failed'
    explanation = ('Gateway forwarding and health checks passed. ' + ('Backend port has only observed loopback listeners; ordinary remote-interface access is restricted by that binding. ' if loopback else 'Bind the backend to loopback or enforce direct access separately. ') + 'This does not establish independently verified external isolation or comprehensive security.') if success else 'Health, forwarding, or configured authentication verification failed. Inspect check results.'
    report = dict(timestamp=now(),state=state,healthy=healthy,forwarded=forwarded,loopback_observed=loopback,checks=checks,explanation=explanation)
    if runtime.db.meta('service_revision:'+service['id']) != revision or not runtime.db.service(service['id']):
        report.update(state='Protection Failed',explanation='Configuration changed during verification. Run verification again for the current configuration.')
        runtime.db.event('verification_failed',report['explanation'],'warning',service)
        runtime.db.save_verification(service['id'],report)
        return report
    runtime.db.execute('UPDATE services SET verification=? WHERE id=?',(json.dumps(report),service['id']))
    runtime.db.save_verification(service['id'],report)
    runtime.db.event('verification_successful' if success else 'verification_failed', explanation, 'info' if success else 'error', service)
    runtime.collector.publish({'type':'verification','service_id':service['id']})
    return report
