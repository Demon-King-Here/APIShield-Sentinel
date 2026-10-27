import asyncio
import hmac
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from app.api.routes import router
from app.config import ROOT, Settings
from app.runtime import Runtime
from app.gateway.listener import GatewayListener
from app.security.authentication import COOKIE,csrf_token,local_peer
from app.api.authentication import router as authentication_router


def create_app(settings=None):
    settings = settings or Settings()
    settings.validate()

    @asynccontextmanager
    async def lifespan(app):
        runtime = Runtime(settings)
        app.state.runtime = runtime
        listener = None
        watcher = None
        try:
            if settings.start_gateway:
                listener = GatewayListener(runtime)
                await listener.refresh()
                watcher = asyncio.create_task(listener.watch())
            runtime.start_monitoring()
            yield
        finally:
            if watcher:
                watcher.cancel()
                await asyncio.gather(watcher,return_exceptions=True)
            if listener:
                await listener.close()
            await runtime.close()

    app = FastAPI(title='APIShield Sentinel',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return JSONResponse({'error':{'code':f'http_{exc.status_code}','message':str(exc.detail)}},status_code=exc.status_code,headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def input_error(request, exc):
        # Pydantic's original error includes input values; omit them to avoid echoing secrets.
        fields = ['.'.join(str(x) for x in e['loc']) for e in exc.errors()]
        return JSONResponse({'error':{'code':'validation_error','message':'Invalid fields: '+', '.join(fields)}},status_code=422)

    @app.middleware('http')
    async def protect_admin(request: Request, call_next):
        def error(status,message):
            return JSONResponse({'error':{'code':f'http_{status}','message':message}},status_code=status)
        allowed_hosts = {'127.0.0.1','localhost','::1',settings.admin_host}
        try:
            host = urlsplit('http://'+request.headers.get('host','')).hostname
            if host not in allowed_hosts:
                return error(400,'Host is not allowed')
        except ValueError:
            return error(400,'Invalid host')
        origin = request.headers.get('origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            return error(403,'Cross-origin administration is forbidden')
        if request.url.path.startswith('/api/'):
            if request.headers.get('sec-fetch-site')=='cross-site':
                return error(403,'Cross-site administration is forbidden')
            if not local_peer(request) and request.url.scheme!='https' and request.url.path!='/api/health':
                return error(403,'Remote administration requires HTTPS')
            runtime=app.state.runtime
            token=request.cookies.get(COOKIE,'')
            session=runtime.auth.session(token)
            request.state.admin_session=session
            request.state.session_token=token if session else ''
            supplied=request.headers.get('authorization','')
            bearer=bool(runtime.settings.admin_token) and supplied.startswith('Bearer ') and hmac.compare_digest(supplied[7:].encode(),runtime.settings.admin_token.encode())
            public=request.url.path in ('/api/session','/api/health','/api/ready','/api/auth/login','/api/auth/setup')
            if not public and ((supplied and not bearer) or not (session or bearer)):
                return error(401,'Administrator login required')
            if request.method not in ('GET','HEAD'):
                if request.headers.get('x-apishield-action') != 'admin':
                    return error(403,'Administrative action header required')
                if session and not bearer and request.url.path not in ('/api/auth/login','/api/auth/setup') and not hmac.compare_digest(request.headers.get('x-csrf-token','').encode(),csrf_token(token).encode()):
                    return error(403,'Valid session CSRF token required')
                if request.headers.get('content-length') and (not request.headers['content-length'].isdigit() or int(request.headers['content-length']) > 65536):
                    return error(413,'Administrative body exceeds 64 KiB')
                body = bytearray()
                try:
                    async with asyncio.timeout(10):
                        async for chunk in request.stream():
                            body.extend(chunk)
                            if len(body)>65536:
                                return error(413,'Administrative body exceeds 64 KiB')
                    request._body = bytes(body)
                except TimeoutError:
                    return error(408,'Administrative request timed out')
        return await call_next(request)

    @app.middleware('http')
    async def security_headers(request: Request,call_next):
        response=await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store' if request.url.path.startswith('/api') else 'no-cache'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
        if request.url.scheme=='https':
            response.headers['Strict-Transport-Security']='max-age=31536000'
        return response

    app.include_router(router)
    app.include_router(authentication_router)
    app.mount('/static',StaticFiles(directory=ROOT/'frontend'),name='static')

    @app.get('/')
    async def index():
        return FileResponse(ROOT/'frontend/index.html')

    return app


app = create_app()


if __name__ == '__main__':
    from app.__main__ import main
    main()
