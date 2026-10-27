"""Explicit offline account recovery by the Windows owner; preserves API/history data."""
import argparse
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
import psutil
from app.config import Settings


def ensure_stopped():
    for process in psutil.process_iter(['cmdline','cwd']):
        try:
            args=process.info.get('cmdline') or []
            directory=process.info.get('cwd')
            if directory and Path(directory).resolve()==ROOT and any(arg in ('app.main:app','app.main','app','app.__main__') for arg in args):
                raise RuntimeError('Stop APIShield first with Stop_APIShield.bat or close its manual server process')
        except (psutil.NoSuchProcess,psutil.AccessDenied):
            continue


def reset_credentials(database):
    ensure_stopped()
    path=Path(database).resolve()
    if not path.is_file():
        raise RuntimeError('No existing database found; start APIShield for first-time setup')
    folder=path.parent/'backups';folder.mkdir(exist_ok=True)
    backup=folder/f'before-admin-reset-{time.time_ns()}.db'
    with closing(sqlite3.connect(path)) as source,closing(sqlite3.connect(backup)) as target:
        source.backup(target)
        with source:
            source.execute('DELETE FROM admin_sessions')
            source.execute('DELETE FROM admin_accounts')
            source.execute('DELETE FROM metadata WHERE key=?',('admin_setup_hash',))
            source.execute('DELETE FROM rate_limits WHERE route IN (?,?,?)',('__admin_login','__admin_setup','__admin_password'))
            source.execute("INSERT INTO audit(timestamp,action,detail) VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'),'administrator_reset','Offline local owner reset administrator credentials; API configuration and monitoring data preserved')")
    return backup


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-local-reset',action='store_true',help='Explicitly reset the local administrator and revoke all login sessions')
    args=parser.parse_args()
    if not args.confirm_local_reset:
        parser.error('Use --confirm-local-reset only to recover your own administrator account while APIShield is stopped')
    try:
        backup=reset_credentials(Settings().db_path)
    except (RuntimeError,sqlite3.Error) as exc:
        raise SystemExit(str(exc)) from None
    print(f'Administrator account reset. Previous database saved at: {backup}\nStart_APIShield.bat will create a fresh one-time setup code. Existing APIs and history are preserved.')
