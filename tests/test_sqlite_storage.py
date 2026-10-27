import json
import sqlite3
from app.database.db import Database,now
from app.gateway.rate_limiter import RateLimiter


def test_additive_migration_keeps_existing_data(tmp_path):
    path=tmp_path/'old.db'
    with sqlite3.connect(path) as original:
        original.executescript('CREATE TABLE services(id TEXT PRIMARY KEY,config TEXT NOT NULL,verification TEXT); PRAGMA user_version=1;')
        original.execute('INSERT INTO services VALUES (?,?,NULL)',('existing',json.dumps({'name':'Keep me'})))
    db=Database(path)
    assert db.service('existing')['name']=='Keep me'
    assert db.storage_info()['schema_version']==3
    assert 'rate_limits' in db.storage_info()['tables']
    db.close()


def test_rate_window_survives_restart_and_blocked_attempts_do_not_extend_it(tmp_path,monkeypatch):
    clock=[1000.0]
    monkeypatch.setattr('app.gateway.rate_limiter.time.time',lambda:clock[0])
    path=tmp_path/'persistent.db'
    db=Database(path)
    limiter=RateLimiter(db=db)
    assert limiter.check('service','192.168.1.10',2,10)[0]
    assert limiter.check('service','192.168.1.10',2,10)[0]
    db.close()
    db=Database(path)
    limiter=RateLimiter(db=db)
    assert not limiter.check('service','192.168.1.10',2,10)[0]
    clock[0]=1005
    assert not limiter.check('service','192.168.1.10',2,10)[0]
    rows=db.query('SELECT * FROM rate_limits')
    assert rows[0]['expires_at']==1010
    assert '192.168.1.10' not in rows[0]['client_hash']
    clock[0]=1010.1
    assert limiter.check('service','192.168.1.10',2,10)[0]
    limiter.clear_route('service')
    assert db.query('SELECT * FROM rate_limits')==[]
    db.close()


def test_persistent_rate_state_has_capacity_bound(tmp_path):
    db=Database(tmp_path/'bounded.db')
    limiter=RateLimiter(capacity=1,db=db)
    assert limiter.check('route','client-one',1,60)[0]
    assert not limiter.check('route','client-two',1,60)[0]
    assert len(db.query('SELECT * FROM rate_limits'))==1
    db.close()


def test_scan_system_and_verification_histories_persist(tmp_path):
    path=tmp_path/'history.db'
    db=Database(path)
    db.save_scan({'timestamp':now(),'success':True,'listeners':[]})
    db.save_scan({'timestamp':now(),'success':False,'listeners':[]})
    db.save_verification('api',{'timestamp':now(),'state':'Gateway Managed'})
    db.save_verification('api',{'timestamp':now(),'state':'Protection Failed'})
    db.save_system_sample({'cpu':12.5,'memory':40.5})
    db.close()
    db=Database(path)
    counts=db.storage_info()['tables']
    assert counts['discovery_scans']==2 and counts['verification_history']==2 and counts['system_samples']==1
    db.close()


def test_backup_is_consistent_and_requires_admin(upstream,tmp_path):
    admin,gateway,runtime=upstream
    gateway.get('/student/student')
    assert admin.get('/api/database',headers={'Authorization':''}).status_code==401
    assert admin.post('/api/database/backup',headers={'Authorization':''}).status_code==401
    response=admin.post('/api/database/backup')
    assert response.status_code==200 and response.content.startswith(b'SQLite format 3')
    backup=tmp_path/'download.db';backup.write_bytes(response.content)
    with sqlite3.connect(backup) as source:
        assert source.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert source.execute('SELECT COUNT(*) FROM services').fetchone()[0]==3
        assert source.execute('SELECT COUNT(*) FROM requests').fetchone()[0]==1
    assert not list((runtime.db.path.parent/'backups').glob('sentinel-download-*.db'))
    info=admin.get('/api/database').json()
    assert info['engine']=='SQLite' and info['schema_version']==3 and info['tables']['rate_limits']==1


def test_history_apis_and_clear_preserve_configuration_and_quotas(upstream):
    admin,gateway,runtime=upstream
    runtime.db.save_scan({'timestamp':now(),'success':True,'listeners':[]})
    runtime.db.save_verification('service-student',{'timestamp':now(),'state':'Gateway Managed'})
    gateway.get('/student/student')
    assert len(admin.get('/api/discovery/history').json())==1
    assert len(admin.get('/api/services/service-student/verification-history').json())==1
    assert admin.get('/api/metrics/system').json()
    assert admin.post('/api/history/clear').status_code==200
    info=admin.get('/api/database').json()
    assert info['tables']['discovery_scans']==0 and info['tables']['verification_history']==0
    assert info['tables']['services']==3 and info['tables']['rate_limits']==1 and info['tables']['audit']>=1
