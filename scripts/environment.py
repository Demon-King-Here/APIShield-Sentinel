"""Start/stop this checkout's owned Sentinel process."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import webbrowser
import httpx
import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from app.config import Settings
RUNTIME = ROOT/'runtime'


def owned(record):
    try:
        process = psutil.Process(record['pid'])
        args = process.cmdline()
        if abs(process.create_time()-record['created']) < .1 and record['module'] in args and Path(process.cwd()).resolve()==ROOT:
            return process
    except (psutil.Error, OSError, ValueError):
        pass
    return None


def stop(records):
    for record in reversed(records):
        process = owned(record)
        if not process:
            print(f'Skipped {record["name"]}: original owned process no longer present.')
            continue
        # Windows virtualenv launchers may own an actual Python child. Every
        # descendant is rechecked for the same module before termination.
        children = []
        for child in process.children(recursive=True):
            try:
                if record['module'] in child.cmdline() and Path(child.cwd()).resolve()==ROOT:
                    children.append(child)
            except psutil.Error:
                pass
        for child in children:
            child.terminate()
        process.terminate()
        psutil.wait_procs(children+[process],timeout=5)
        print(f'Stopped owned {record["name"]} process.')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['start','stop'])
    parser.add_argument('--open-browser',action='store_true',help='Open the dashboard after startup or reuse an already-running owned environment')
    arguments=parser.parse_args()
    action=arguments.action
    registry = RUNTIME/'processes.json'
    RUNTIME.mkdir(exist_ok=True)
    records=json.loads(registry.read_text()) if registry.exists() else []
    if action=='stop':
        stop(records)
        registry.unlink(missing_ok=True)
        return
    settings = Settings()
    settings.validate()
    jobs = [('sentinel','app.main:app',settings.admin_port)]
    dashboard_host={'0.0.0.0':'127.0.0.1','::':'::1'}.get(settings.admin_host,settings.admin_host)
    dashboard_host=f'[{dashboard_host}]' if ':' in dashboard_host else dashboard_host
    dashboard_url=f'http://{dashboard_host}:{settings.admin_port}'
    running=[record for record in records if owned(record)]
    if running:
        expected={name for name,_,_ in jobs}
        if {record['name'] for record in running}==expected:
            try:
                with httpx.Client(trust_env=False,timeout=2) as client:
                    response=client.get(dashboard_url+'/api/health')
                    healthy=response.status_code==200 and response.json().get('status')=='ok'
            except (httpx.HTTPError,ValueError):
                healthy=False
            if healthy:
                print(f'APIShield is already running.\nDashboard: {dashboard_url}')
                if (Path(settings.db_path).parent/'admin-setup-code.txt').exists():
                    print(f'Create your administrator in the browser. Setup code file: {Path(settings.db_path).parent / "admin-setup-code.txt"}')
                if arguments.open_browser:
                    webbrowser.open(dashboard_url)
                return
        raise SystemExit('An incomplete owned environment is running. Stop it with the matching launcher, then start it again.')
    # Check every selected port before launching; never evict an existing service.
    addresses = [(settings.admin_host if name=='sentinel' else '127.0.0.1', port) for name,_,port in jobs]
    if settings.gateway_host:
        addresses.append((settings.gateway_host,settings.gateway_port))
    for host,port in addresses:
        with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET) as sock:
            try:
                if hasattr(socket,'SO_EXCLUSIVEADDRUSE'):
                    sock.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
                sock.bind((host,port))
            except OSError:
                raise SystemExit(f'Port {port} is already in use. Stop your own conflicting service or select another port.') from None
    records=[]
    try:
        for name,module,port in jobs:
            host=os.getenv('APISHIELD_ADMIN_HOST','127.0.0.1') if name=='sentinel' else '127.0.0.1'
            args=[sys.executable,'-m','uvicorn',module,'--host',host,'--port',str(port),'--no-proxy-headers','--no-access-log',
                  '--no-server-header','--limit-concurrency','100','--timeout-graceful-shutdown','10']
            with (RUNTIME/f'{name}.log').open('w',encoding='utf-8') as log:
                process=subprocess.Popen(args,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,
                    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),start_new_session=os.name!='nt')
            record=dict(pid=process.pid,created=psutil.Process(process.pid).create_time(),module=module,name=name)
            records.append(record)
            registry.write_text(json.dumps(records,indent=2))
            check_host={'0.0.0.0':'127.0.0.1','::':'::1'}.get(host,host)
            check_host=f'[{check_host}]' if ':' in check_host else check_host
            url=f'http://{check_host}:{port}'+('/api/health' if name=='sentinel' else '/health')
            with httpx.Client(trust_env=False,timeout=.8) as client:
                for _ in range(80):
                    if process.poll() is not None:
                        raise RuntimeError(f'{name} exited. Inspect runtime/{name}.log.')
                    try:
                        response=client.get(url)
                        if response.status_code==200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(.15)
                else:
                    raise RuntimeError(f'{name} did not become ready. Inspect runtime/{name}.log.')
            print(f'{name}: ready on {host}:{port}')
    except Exception:
        stop(records)
        registry.unlink(missing_ok=True)
        raise
    gateway_host = f'[{settings.gateway_host}]' if settings.gateway_host and ':' in settings.gateway_host else settings.gateway_host
    scheme = 'https' if settings.gateway_certfile else 'http'
    gateway = f'{scheme}://{gateway_host}:{settings.gateway_port}' if gateway_host else f'Waiting for selected adapter {settings.gateway_interface}'
    print(f'\nDashboard: {dashboard_url}\nGateway: {gateway}\nLogs: {RUNTIME}\nStop: Stop_APIShield.bat')
    if (Path(settings.db_path).parent/'admin-setup-code.txt').exists():
        print(f'Create your administrator in the browser. Setup code file: {Path(settings.db_path).parent / "admin-setup-code.txt"}')
    if arguments.open_browser:
        webbrowser.open(dashboard_url)


if __name__=='__main__':
    main()
