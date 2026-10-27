import asyncio
import csv
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from fastapi import APIRouter, HTTPException, Request, Query
from fastapi.responses import Response, StreamingResponse, FileResponse, JSONResponse
from starlette.background import BackgroundTask
from app.database.models import ServiceInput, Policy
from app.discovery.windows_scanner import scan
from app.discovery.classification import classify
from app.security.validation import validate_backend
from app.security.verification import verify
from app.security.authentication import csrf_token,local_peer

router = APIRouter(prefix='/api')


def rt(request):
    return request.app.state.runtime


def service_or_404(runtime, sid):
    service = runtime.db.service(sid)
    if not service:
        raise HTTPException(404,'API configuration not found')
    return service


def export_rows(rows, format, filename):
    if format == 'csv':
        buffer = io.StringIO(newline='')
        if rows:
            writer = csv.DictWriter(buffer, fieldnames=rows[0].keys())
            writer.writeheader()
            # Neutralize spreadsheet formula cells in CSV exports.
            writer.writerows({k:("'"+str(v) if str(v).lstrip().startswith(('=','+','-','@')) else v) for k,v in row.items()} for row in rows)
        return Response(buffer.getvalue(),media_type='text/csv',headers={'Content-Disposition':f'attachment; filename="{filename}.csv"'})
    return Response(json.dumps(rows,indent=2),media_type='application/json',headers={'Content-Disposition':f'attachment; filename="{filename}.json"'})


@router.get('/health')
async def health(request: Request):
    runtime = rt(request)
    try:
        if not runtime.gateway_url:
            raise RuntimeError('Gateway waiting for selected adapter')
        checked_url = runtime.gateway_url
        response = await runtime.client.get(checked_url+'/_sentinel/health',timeout=1)
        runtime.gateway_healthy = response.status_code == 200 and runtime.gateway_url == checked_url
    except Exception:
        runtime.gateway_healthy = False
    return {'status':'ok','gateway':runtime.gateway_healthy,'gateway_port':runtime.settings.gateway_port,'gateway_url':runtime.gateway_url,'gateway_state':runtime.gateway_state,'firewall_changes':False}


@router.get('/session')
async def session(request: Request):
    runtime = rt(request)
    current=request.state.admin_session
    return dict(authenticated=bool(current),setup_required=not bool(runtime.auth.account()),
                setup_local=local_peer(request),username=current['username'] if current else None,
                csrf_token=csrf_token(request.state.session_token) if current else None)


@router.get('/ready')
async def ready(request: Request):
    status = await health(request)
    return JSONResponse({'status':'ready' if status['gateway'] else 'not_ready'},
                        status_code=200 if status['gateway'] else 503)


@router.get('/settings')
def settings(request: Request):
    runtime = rt(request)
    return dict(admin_host=runtime.settings.admin_host,admin_port=runtime.settings.admin_port,
                gateway_host=runtime.settings.gateway_host,gateway_port=runtime.settings.gateway_port,
                gateway_interface=runtime.settings.gateway_interface,gateway_url=runtime.gateway_url,
                gateway_state=runtime.gateway_state,interface_poll_seconds=3,
                upstream_hosts=sorted(runtime.settings.upstream_hosts),retained_requests=runtime.settings.retention,
                authentication='Password login with revocable sessions',automation_token_configured=bool(runtime.settings.admin_token),firewall_changes=False,
                monitoring_scope='Gateway HTTP requests only',database_schema=runtime.db.SCHEMA_VERSION,
                database_path=str(runtime.db.path),storage_engine='SQLite',external_probes='Not performed')


@router.get('/database')
def database_status(request: Request):
    return rt(request).db.storage_info()


@router.post('/database/backup')
async def database_backup(request: Request):
    runtime=rt(request)
    runtime.db.audit('database_backup_downloaded','Consistent SQLite snapshot requested by authenticated administrator')
    path=await asyncio.to_thread(runtime.db.backup_file)
    return FileResponse(path,filename='apishield-sentinel-backup.db',media_type='application/vnd.sqlite3',
                        background=BackgroundTask(path.unlink,missing_ok=True))


@router.get('/discovery/history')
def discovery_history(request: Request, limit: int = Query(20,ge=1,le=100)):
    return [dict(id=r['id'],**json.loads(r['data'])) for r in rt(request).db.query('SELECT * FROM discovery_scans ORDER BY id DESC LIMIT ?',(limit,))]


@router.get('/services/{sid}/verification-history')
def verification_history(sid: str, request: Request, limit: int = Query(20,ge=1,le=100)):
    return [dict(id=r['id'],**json.loads(r['data'])) for r in rt(request).db.query('SELECT * FROM verification_history WHERE service_id=? ORDER BY id DESC LIMIT ?',(sid,limit))]


@router.get('/metrics/system')
def system_history(request: Request, limit: int = Query(120,ge=1,le=1000)):
    return [dict(timestamp=r['timestamp'],**json.loads(r['data'])) for r in rt(request).db.query('SELECT * FROM system_samples ORDER BY id DESC LIMIT ?',(limit,))][::-1]


@router.post('/discovery/scan')
async def discovery(request: Request):
    runtime = rt(request)
    if runtime.scan_lock.locked():
        raise HTTPException(409,'A discovery scan is already running')
    async with runtime.scan_lock:
        result = await asyncio.to_thread(scan, runtime.db.services_with_evidence())
        runtime.db.save_scan(result)
        if result['success']:
            with runtime.db.lock, runtime.db.conn:
                runtime.db.conn.execute('DELETE FROM listeners')
                runtime.db.conn.executemany('INSERT INTO listeners(data) VALUES (?)',[(json.dumps(row),) for row in result['listeners']])
            runtime.db.meta('last_scan',result['timestamp'])
            runtime.db.event('port_discovered',f'Read-only scan observed {len(result["listeners"])} listeners')
            count = sum(r['security_status']=='Potentially Exposed' for r in result['listeners'])
            if count:
                runtime.db.event('potential_exposure_identified',f'{count} network-bound listeners need review; external access is unconfirmed','warning')
        runtime.db.meta('scan_result',{k:v for k,v in result.items() if k!='listeners'})
        runtime.db.audit('discovery_scan',result['source'])
        runtime.collector.publish({'type':'scan'})
        return result


@router.get('/discovery/ports')
def ports(request: Request, q: str = '', port: int | None = None, process: str = '', classification: str = '', format: str = Query(default='',pattern='^(|csv|json)$')):
    runtime = rt(request)
    services = runtime.db.services_with_evidence()
    rows = [classify(json.loads(r['data']),services) for r in runtime.db.query('SELECT data FROM listeners')]
    rows = [r for r in rows if (port is None or r['port']==port) and process.lower() in r.get('process','Unknown').lower() and classification.lower() in r['classification'].lower() and q.lower() in json.dumps(r).lower()]
    if format:
        return export_rows(rows,format,'listeners')
    return {'listeners':rows,'scan':runtime.db.meta('scan_result')}


@router.get('/services')
def services(request: Request):
    runtime = rt(request)
    rows = runtime.db.services_with_evidence()
    listeners = [json.loads(r['data']) for r in runtime.db.query('SELECT data FROM listeners')]
    for service in rows:
        port = urlsplit(service['backend_url']).port
        matches = [r for r in listeners if r['port']==port]
        stats = runtime.db.query('SELECT COUNT(*) total, MAX(timestamp) last_observed FROM requests WHERE service_id=?',(service['id'],))[0]
        service.update(backend_port=port,processes=matches,**stats)
        service['rps'] = runtime.db.query("SELECT COUNT(*)/10.0 rps FROM requests WHERE service_id=? AND timestamp>=?",(service['id'],(datetime.now(timezone.utc)-timedelta(seconds=10)).isoformat()))[0]['rps']
        service['security_state'] = ('Needs Review' if not service['enabled'] else service['verification']['state'] if service['verification'] else
                                     'Gateway Managed' if service['forwarded_observed'] else 'Needs Review')
    return rows


def validate_service(runtime, data, sid=None):
    try:
        data.backend_url = validate_backend(data.backend_url,runtime.settings)
    except ValueError as exc:
        raise HTTPException(422,str(exc)) from None
    if data.gateway_path in {'/api','/static','/_sentinel'}:
        raise HTTPException(422,'Gateway path is reserved')
    if any(s['gateway_path']==data.gateway_path and s['id']!=sid for s in runtime.db.services()):
        raise HTTPException(409,'Gateway path already exists')


@router.post('/services',status_code=201)
async def add_service(data: ServiceInput, request: Request):
    runtime = rt(request)
    validate_service(runtime,data)
    sid = uuid.uuid4().hex
    runtime.db.save_service(sid,data.model_dump())
    runtime.db.audit('api_route_added',f'{sid}: {data.name}')
    runtime.db.event('api_route_changed','API route added',service=runtime.db.service(sid))
    return runtime.db.service(sid)


@router.get('/services/{sid}')
def get_service(sid: str, request: Request):
    return service_or_404(rt(request),sid)


@router.put('/services/{sid}')
async def update_service(sid: str, data: ServiceInput, request: Request):
    runtime = rt(request)
    service_or_404(runtime,sid)
    validate_service(runtime,data,sid)
    runtime.db.save_service(sid,data.model_dump())
    runtime.limiter.clear_route(sid)
    runtime.db.audit('api_route_updated',f'{sid}: {data.name}')
    runtime.db.event('api_route_changed','Route configuration updated; old verification invalidated',service=runtime.db.service(sid))
    return runtime.db.service(sid)


@router.delete('/services/{sid}')
async def delete_service(sid: str, request: Request):
    runtime = rt(request)
    service = service_or_404(runtime,sid)
    runtime.db.execute('DELETE FROM services WHERE id=?',(sid,))
    runtime.db.execute('DELETE FROM metadata WHERE key=?',('service_revision:'+sid,))
    runtime.limiter.clear_route(sid)
    runtime.db.audit('api_route_removed',f'{sid}: {service["name"]}; backend process unchanged')
    runtime.db.event('api_route_changed','Gateway route removed; original API process remains running',service=service)
    return {'removed':sid,'backend_process_unchanged':True}


@router.get('/policies')
def policies(request: Request):
    return [{'service_id':s['id'],'api_name':s['name'],**s['policy']} for s in rt(request).db.services()]


@router.put('/services/{sid}/policy')
async def update_policy(sid: str, data: Policy, request: Request):
    runtime = rt(request)
    service = service_or_404(runtime,sid)
    config = {k:v for k,v in service.items() if k not in ('id','verification')}
    config['policy'] = data.model_dump()
    runtime.db.save_service(sid,config)
    runtime.limiter.clear_route(sid)
    runtime.db.audit('policy_updated',f'{sid}; verification invalidated; rate window reset')
    return data


@router.post('/services/{sid}/verify')
async def verification(sid: str, request: Request):
    runtime = rt(request)
    if not runtime.gateway_url:
        raise HTTPException(503,'Gateway is waiting for the selected network adapter')
    service = service_or_404(runtime,sid)
    try:
        validate_backend(service['backend_url'],runtime.settings)
    except ValueError as exc:
        raise HTTPException(422,str(exc)) from None
    return await verify(runtime,service)


@router.get('/metrics/overview')
def overview(request: Request):
    return rt(request).collector.overview()


@router.get('/metrics/traffic')
def traffic(request: Request):
    return rt(request).collector.traffic()


@router.get('/traffic')
def requests(request: Request, service_id: str = '', q: str = '', status: int | None = None, since: str = '', until: str = '', decision: str = '', limit: int = Query(100,ge=1,le=1000), format: str = Query('',pattern='^(|csv|json)$')):
    clauses, values = [], []
    for col, value, op in [('service_id',service_id,'='),('status',status,'='),('timestamp',since,'>='),('timestamp',until,'<='),('decision',decision,'=')]:
        if value is not None and value != '':
            clauses.append(f'{col}{op}?'); values.append(value)
    if q:
        clauses.append('(path LIKE ? OR api_name LIKE ? OR error LIKE ?)'); values.extend([f'%{q}%']*3)
    rows = rt(request).db.query('SELECT * FROM requests'+(' WHERE '+' AND '.join(clauses) if clauses else '')+' ORDER BY id DESC LIMIT ?',values+[limit])
    return export_rows(rows,format,'traffic') if format else rows


@router.get('/events')
def events(request: Request, service_id: str = '', type: str = '', q: str = '', since: str = '', until: str = '', severity: str = '', limit: int = Query(100,ge=1,le=1000), format: str = Query('',pattern='^(|csv|json)$')):
    clauses, values = [], []
    for col,value,op in [('service_id',service_id,'='),('type',type,'='),('severity',severity,'='),('timestamp',since,'>='),('timestamp',until,'<=')]:
        if value:
            clauses.append(f'{col}{op}?'); values.append(value)
    if q:
        clauses.append('(detail LIKE ? OR api_name LIKE ?)'); values.extend([f'%{q}%']*2)
    rows = rt(request).db.query('SELECT * FROM events'+(' WHERE '+' AND '.join(clauses) if clauses else '')+' ORDER BY id DESC LIMIT ?',values+[limit])
    return export_rows(rows,format,'security-events') if format else rows


@router.get('/audit')
def audit(request: Request, format: str = Query('',pattern='^(|csv|json)$')):
    rows = rt(request).db.query('SELECT * FROM audit ORDER BY id DESC LIMIT 1000')
    return export_rows(rows,format,'audit') if format else rows


@router.get('/stream')
async def stream(request: Request):
    async def disconnected():
        return await request.is_disconnected() or bool(request.state.session_token and not rt(request).auth.session(request.state.session_token,touch=False))
    return StreamingResponse(rt(request).collector.stream(disconnected),media_type='text/event-stream',headers={'Cache-Control':'no-store','X-Accel-Buffering':'no'})


@router.post('/history/clear')
def clear_history(request: Request):
    runtime = rt(request)
    with runtime.db.lock, runtime.db.conn:
        for table in ('requests','events','aggregates','discovery_scans','verification_history','system_samples'):
            runtime.db.conn.execute(f'DELETE FROM {table}')
    runtime.db.audit('history_cleared','Monitoring history cleared. API configurations, latest discovery/verification, rate windows and audit log preserved.')
    runtime.collector.publish({'type':'history_cleared'})
    return {'cleared':True,'configurations_preserved':True,'audit_preserved':True}
