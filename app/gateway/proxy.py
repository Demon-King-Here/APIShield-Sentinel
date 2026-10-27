import asyncio
import hmac
import logging
import os
import time
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from app.database.db import now
from app.security.validation import safe_request_path, path_matches, validate_backend
from app.security.authentication import COOKIE

logger = logging.getLogger('apishield.access')
HOP_HEADERS = {'connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade','host'}
FORWARDED_HEADERS = {'forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto','x-real-ip','x-api-key','x-apishield-internal','x-csrf-token','content-length'}


class UpstreamPolicyError(Exception):
    pass


def filtered_headers(headers, request=False):
    pairs = list(headers.multi_items() if hasattr(headers, 'multi_items') else headers.items())
    connection = {v.strip().lower() for k, val in pairs if k.lower() == 'connection' for v in val.split(',')}
    blocked = HOP_HEADERS | connection | (FORWARDED_HEADERS if request else set())
    result=[]
    for key,value in pairs:
        if key.lower() in blocked or key.lower().startswith('x-forwarded-'):
            continue
        if request and key.lower()=='cookie':
            value='; '.join(part.strip() for part in value.split(';') if part.partition('=')[0].strip().lower()!=COOKIE.lower())
            if not value:
                continue
        if not request and key.lower()=='set-cookie' and value.partition('=')[0].strip().lower()==COOKIE.lower():
            continue
        result.append((key,value))
    return result


@asynccontextmanager
async def upstream_stream(client, method, target, content, headers, timeout):
    # Construct a standalone request: shared clients must never merge a previous
    # user's upstream cookies or authentication into another user's request.
    outbound = httpx.Request(method, target, content=content, headers=headers,
                             extensions={'timeout':httpx.Timeout(timeout).as_dict()})
    response = await client.send(outbound,stream=True,follow_redirects=False)
    try:
        yield response
    finally:
        await response.aclose()


def create_gateway(runtime):
    app = FastAPI(title='APIShield Gateway', docs_url=None, redoc_url=None, openapi_url=None)

    @app.get('/_sentinel/health')
    async def health():
        return {'status':'ok','component':'gateway'}

    @app.api_route('/{path:path}', methods=['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT'])
    async def forward(request: Request, path: str):
        started = time.perf_counter()
        service = None
        size = 0
        upstream_status = None
        rate_decision = 'not evaluated'
        decision = 'allowed'
        category = None
        response = None
        safe_path = '/[rejected-path]'

        def reject(status, code, message, retry=None):
            nonlocal decision, category
            decision, category = 'blocked', code
            return JSONResponse({'error':{'code':code,'message':message}}, status_code=status,
                                headers={'Retry-After':str(retry)} if retry else None)

        try:
            safe_path = safe_request_path(request.scope.get('raw_path', request.url.path))
            service = next((s for s in sorted(runtime.db.services(), key=lambda s:len(s['gateway_path']), reverse=True)
                            if s['enabled'] and path_matches(safe_path, s['gateway_path'])), None)
            if not service:
                response = reject(404,'route_not_found','No enabled gateway route matches this path')
            else:
                try:
                    validate_backend(service['backend_url'],runtime.settings)
                except ValueError:
                    raise UpstreamPolicyError from None
                policy = service['policy']
                if request.method not in policy['methods']:
                    response = reject(405,'method_rejected','HTTP method is not allowed by this route policy')
                elif not any(path_matches(safe_path, p) for p in policy['allowed_paths']):
                    response = reject(403,'path_rejected','Path is not allowed by this route policy')
                elif policy['client_key_env'] and (not os.getenv(policy['client_key_env']) or not hmac.compare_digest(request.headers.get('x-api-key','').encode(), os.getenv(policy['client_key_env'],'').encode())):
                    response = reject(401,'authentication_rejected','A valid gateway X-API-Key is required')
                else:
                    # Verification uses this same policy evaluator without consuming client quota.
                    # Only an unguessable process secret on a local socket can bypass quota.
                    internal = bool(runtime.internal_secret) and request.client.host in ('127.0.0.1','::1') and hmac.compare_digest(request.headers.get('x-apishield-internal','').encode(), runtime.internal_secret.encode())
                    allowed, retry = (True,0) if internal else runtime.limiter.check(service['id'], request.client.host, policy['limit'], policy['window'])
                    rate_decision = 'internal verification' if internal else 'allowed' if allowed else 'exceeded'
                    if not allowed:
                        response = reject(429,'rate_limit_exceeded','Per-client route request limit exceeded', retry)
                    elif request.headers.get('content-length') and (not request.headers['content-length'].isdigit() or int(request.headers['content-length']) > policy['max_body']):
                        response = reject(413,'body_too_large','Request body exceeds the configured maximum')
                    else:
                        chunks = []
                        async with asyncio.timeout(10):
                            async for chunk in request.stream():
                                size += len(chunk)
                                if size > policy['max_body']:
                                    response = reject(413,'body_too_large','Request body exceeds the configured maximum')
                                    break
                                chunks.append(chunk)
                        if response is None:
                            upstream_path = safe_path[len(service['gateway_path']):] or '/' if service['strip_prefix'] else safe_path
                            target = httpx.URL(service['backend_url'] + upstream_path).copy_with(query=request.scope['query_string'])
                            headers = filtered_headers(request.headers, request=True)
                            upstream_env = policy['upstream_token_env']
                            if upstream_env:
                                token = os.getenv(upstream_env)
                                if not token:
                                    response = reject(503,'credential_unavailable','Configured upstream credential is unavailable')
                                else:
                                    headers = [(k,v) for k,v in headers if k.lower() != 'authorization'] + [('Authorization',f'Bearer {token}')]
                            if response is None:
                                async with asyncio.timeout(service['timeout']):
                                    async with upstream_stream(runtime.client, request.method, target, b''.join(chunks), headers, service['timeout']) as upstream:
                                        upstream_status = upstream.status_code
                                        body = bytearray()
                                        async for chunk in upstream.aiter_raw():
                                            body.extend(chunk)
                                            if len(body) > 8*1024*1024:
                                                raise ValueError('upstream_response_too_large')
                                        response = Response(bytes(body), status_code=upstream.status_code)
                                        response.raw_headers = [(k.encode('latin-1'),v.encode('latin-1')) for k,v in filtered_headers(upstream.headers) if k.lower() != 'content-length']
                                        response.raw_headers.append((b'content-length',str(len(body)).encode()))
                                        response.headers['X-APIShield-Gateway'] = 'Sentinel'
        except UpstreamPolicyError:
            response = reject(503,'upstream_configuration_rejected','Upstream is not permitted by the current host restrictions')
        except ValueError as exc:
            if str(exc) == 'upstream_response_too_large':
                category = 'upstream_response_too_large'
                response = JSONResponse({'error':{'code':category,'message':'Upstream response exceeds gateway limit'}}, status_code=502)
            else:
                response = reject(400,'invalid_request','Request path or encoding is invalid')
        except (httpx.TimeoutException, TimeoutError):
            category = 'backend_timeout'
            response = JSONResponse({'error':{'code':category,'message':'Request or upstream timed out'}}, status_code=502)
        except httpx.HTTPError:
            category = 'backend_unavailable'
            response = JSONResponse({'error':{'code':category,'message':'Upstream is unavailable'}}, status_code=502)
        except Exception:
            category = 'gateway_error'
            response = JSONResponse({'error':{'code':category,'message':'Gateway could not complete the request'}}, status_code=502)
        duration = round((time.perf_counter()-started)*1000, 3)
        record = dict(timestamp=now(), service_id=service['id'] if service else None, api_name=service['name'] if service else 'Unmatched route',
                      path=safe_path[:256], method=request.method, status=response.status_code, duration=duration, size=size,
                      upstream_status=upstream_status, decision=decision, rate_decision=rate_decision, error=category, origin='gateway')
        runtime.collector.record(record)
        runtime.db.event(category or 'request_allowed', f'{request.method} {safe_path[:128]} → {response.status_code}; {duration:.1f} ms',
                         'warning' if decision=='blocked' else 'error' if response.status_code>=500 else 'info', service)
        logger.info('%s', {k:record[k] for k in ('timestamp','service_id','method','status','duration','decision','error')})
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    return app
