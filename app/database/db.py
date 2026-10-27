import json
import os
import sqlite3
import threading
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing


def now():
    return datetime.now(timezone.utc).isoformat()


class Database:
    SCHEMA_VERSION = 3
    TABLES = ('metadata','services','listeners','requests','events','audit','aggregates',
              'rate_limits','discovery_scans','verification_history','system_samples','admin_accounts','admin_sessions')
    """Small transactions serialized across scanner threads and the event loop."""
    def __init__(self, path, retention=20000):
        self.path = Path(path).resolve()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.retention = retention
        self.writes = 0
        if self.conn.execute('PRAGMA user_version').fetchone()[0] > self.SCHEMA_VERSION:
            self.conn.close()
            raise RuntimeError('Database schema is newer than this application; use a matching application version')
        with self.lock, self.conn:
            self.conn.executescript('''
                PRAGMA journal_mode=WAL;
                PRAGMA busy_timeout=10000;
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS services (id TEXT PRIMARY KEY, config TEXT NOT NULL, verification TEXT);
                CREATE TABLE IF NOT EXISTS listeners (id INTEGER PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, service_id TEXT, api_name TEXT, detail TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
                CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, service_id TEXT, api_name TEXT, path TEXT, method TEXT, status INTEGER, duration REAL, size INTEGER, upstream_status INTEGER, decision TEXT, rate_decision TEXT, error TEXT, origin TEXT);
                CREATE INDEX IF NOT EXISTS requests_time ON requests(timestamp);
                CREATE INDEX IF NOT EXISTS requests_service ON requests(service_id, timestamp);
                CREATE TABLE IF NOT EXISTS aggregates (bucket TEXT NOT NULL, service_id TEXT NOT NULL, total INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, errors INTEGER DEFAULT 0, latency REAL DEFAULT 0, PRIMARY KEY(bucket, service_id));
            ''')
            # Additive migration: no existing configuration/history is replaced.
            self.conn.execute('CREATE TABLE IF NOT EXISTS rate_limits (route TEXT NOT NULL, client_hash TEXT NOT NULL, timestamps TEXT NOT NULL, expires_at REAL NOT NULL, PRIMARY KEY(route,client_hash))')
            self.conn.execute('CREATE INDEX IF NOT EXISTS rate_expiry ON rate_limits(expires_at)')
            self.conn.execute('CREATE TABLE IF NOT EXISTS discovery_scans (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, data TEXT NOT NULL)')
            self.conn.execute('CREATE TABLE IF NOT EXISTS verification_history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, service_id TEXT NOT NULL, data TEXT NOT NULL)')
            self.conn.execute('CREATE INDEX IF NOT EXISTS verification_service_time ON verification_history(service_id,timestamp)')
            self.conn.execute('CREATE TABLE IF NOT EXISTS system_samples (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, data TEXT NOT NULL)')
            self.conn.execute('CREATE INDEX IF NOT EXISTS system_sample_time ON system_samples(timestamp)')
            self.conn.execute('CREATE TABLE IF NOT EXISTS admin_accounts (id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created TEXT NOT NULL)')
            self.conn.execute('CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL, expires_at REAL NOT NULL)')
            self.conn.execute('CREATE INDEX IF NOT EXISTS admin_session_expiry ON admin_sessions(expires_at)')
            self.conn.execute('PRAGMA user_version=3')

    def query(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def execute(self, sql, args=()):
        with self.lock, self.conn:
            return self.conn.execute(sql, args).lastrowid

    def meta(self, key, value=None):
        if value is not None:
            self.execute('INSERT OR REPLACE INTO metadata VALUES (?, ?)', (key, json.dumps(value)))
        rows = self.query('SELECT value FROM metadata WHERE key=?', (key,))
        return json.loads(rows[0]['value']) if rows else None

    def services(self):
        return [dict(json.loads(r['config']), id=r['id'], verification=json.loads(r['verification']) if r['verification'] else None) for r in self.query('SELECT * FROM services')]

    def service(self, sid):
        return next((s for s in self.services() if s['id'] == sid), None)

    def services_with_evidence(self):
        """One shared source of forwarding evidence for management views."""
        with self.lock:
            services = self.services()
            for service in services:
                revision = self.meta('service_revision:'+service['id']) or ''
                service['forwarded_observed'] = bool(self.query(
                    'SELECT id FROM requests WHERE service_id=? AND upstream_status IS NOT NULL AND timestamp>=? LIMIT 1',
                    (service['id'],revision)))
            return services

    def save_service(self, sid, config):
        with self.lock, self.conn:
            self.conn.execute('INSERT INTO services VALUES (?, ?, NULL) ON CONFLICT(id) DO UPDATE SET config=excluded.config, verification=NULL', (sid, json.dumps(config)))
            self.conn.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)',('service_revision:'+sid,json.dumps(now())))

    def event(self, kind, detail, severity='info', service=None):
        self.execute('INSERT INTO events(timestamp,type,severity,service_id,api_name,detail) VALUES (?,?,?,?,?,?)',
                     (now(), kind, severity, service['id'] if service else None, service['name'] if service else None, detail))
        self.execute('DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM events)',(self.retention,))

    def audit(self, action, detail):
        self.execute('INSERT INTO audit(timestamp,action,detail) VALUES (?,?,?)', (now(), action, detail))
        self.execute('DELETE FROM audit WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM audit)',(self.retention,))

    def save_scan(self, result):
        with self.lock,self.conn:
            self.conn.execute('INSERT INTO discovery_scans(timestamp,data) VALUES (?,?)',(result['timestamp'],json.dumps(result)))
            self.conn.execute('DELETE FROM discovery_scans WHERE id <= (SELECT COALESCE(MAX(id),0)-1000 FROM discovery_scans)')

    def save_verification(self, sid, result):
        with self.lock,self.conn:
            self.conn.execute('INSERT INTO verification_history(timestamp,service_id,data) VALUES (?,?,?)',(result['timestamp'],sid,json.dumps(result)))
            self.conn.execute('DELETE FROM verification_history WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM verification_history)',(self.retention,))

    def save_system_sample(self, data):
        with self.lock,self.conn:
            self.conn.execute('INSERT INTO system_samples(timestamp,data) VALUES (?,?)',(now(),json.dumps(data)))
            self.conn.execute('DELETE FROM system_samples WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM system_samples)',(self.retention,))

    def storage_info(self):
        with self.lock:
            return dict(engine='SQLite',path=str(self.path),schema_version=self.conn.execute('PRAGMA user_version').fetchone()[0],
                sqlite_version=sqlite3.sqlite_version,journal_mode=self.conn.execute('PRAGMA journal_mode').fetchone()[0],
                size_bytes=sum(p.stat().st_size for p in (self.path,Path(str(self.path)+'-wal'),Path(str(self.path)+'-shm')) if p.exists()),
                tables={table:self.conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in self.TABLES},
                retention=dict(history_rows=self.retention,discovery_scans=1000,aggregate_days=30,system_interval_seconds=10),
                excluded=['Plaintext passwords, raw session/bearer tokens, cookies and full request bodies','Live sockets and SSE queues'])

    def backup_file(self):
        folder=self.path.parent/'backups'
        folder.mkdir(exist_ok=True)
        descriptor,filename=tempfile.mkstemp(prefix='sentinel-download-',suffix='.db',dir=folder)
        os.close(descriptor)
        try:
            with self.lock,closing(sqlite3.connect(filename)) as backup:
                self.conn.backup(backup)
            return Path(filename)
        except BaseException:
            Path(filename).unlink(missing_ok=True)
            raise

    def record(self, item):
        keys = ['timestamp','service_id','api_name','path','method','status','duration','size','upstream_status','decision','rate_decision','error','origin']
        with self.lock, self.conn:
            self.conn.execute(f'INSERT INTO requests({",".join(keys)}) VALUES ({",".join("?" for _ in keys)})', [item.get(k) for k in keys])
            self.conn.execute('''INSERT INTO aggregates VALUES (?,?,?,?,?,?) ON CONFLICT(bucket,service_id) DO UPDATE SET
                total=total+excluded.total, blocked=blocked+excluded.blocked, errors=errors+excluded.errors, latency=latency+excluded.latency''',
                (item['timestamp'][:16], item.get('service_id') or '', 1, int(item['decision']=='blocked'), int(item['status']>=400), item['duration']))
            self.writes += 1
            if self.writes % 100 == 0:
                for table in ('requests','events','audit'):
                    self.conn.execute(f'DELETE FROM {table} WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM {table})', (self.retention,))
                self.conn.execute('DELETE FROM aggregates WHERE bucket < strftime(\'%Y-%m-%dT%H:%M\',\'now\',\'-30 days\')')

    def close(self):
        with self.lock:
            self.conn.close()
