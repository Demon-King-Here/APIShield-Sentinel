import json
from app.discovery.classification import classify


def test_observed_forwarding_is_sufficient_for_gateway_managed():
    service={'id':'service-inventory','enabled':True,'backend_url':'http://127.0.0.1:5002','verification':None,'forwarded_observed':True}
    row=classify({'local_address':'127.0.0.1','port':5002},[service])
    assert row['security_status']=='Gateway Managed'
    assert row['reachability']=='Unknown'
    assert 'External reachability not tested' in row['explanation']
    network=classify({'local_address':'0.0.0.0','port':5002},[service])
    assert network['security_status']=='Potentially Exposed'


def test_discovery_and_inventory_share_current_forwarding_evidence(upstream):
    admin,gateway,runtime=upstream
    runtime.db.execute('INSERT INTO listeners(data) VALUES (?)',(json.dumps({'local_address':'127.0.0.1','port':5002,'process':'python','pid':123}),))
    def discovery_state():
        return admin.get('/api/discovery/ports?port=5002').json()['listeners'][0]['security_status']
    def inventory_state():
        return next(s for s in admin.get('/api/services').json() if s['id']=='service-inventory')['security_state']
    assert discovery_state()==inventory_state()=='Needs Review'
    assert gateway.get('/inventory/inventory').status_code==200
    assert runtime.db.service('service-inventory')['verification'] is None
    assert discovery_state()==inventory_state()=='Gateway Managed'
    assert admin.put('/api/services/service-inventory/policy',json={'limit':8}).status_code==200
    assert discovery_state()==inventory_state()=='Needs Review'
    assert gateway.get('/inventory/inventory').status_code==200
    assert discovery_state()==inventory_state()=='Gateway Managed'
    config=admin.get('/api/services/service-inventory').json()
    config.pop('id');config.pop('verification');config['enabled']=False
    assert admin.put('/api/services/service-inventory',json=config).status_code==200
    assert discovery_state()==inventory_state()=='Needs Review'


def test_failed_verification_is_not_hidden_by_forwarding_history(upstream):
    admin,gateway,runtime=upstream
    runtime.db.execute('INSERT INTO listeners(data) VALUES (?)',(json.dumps({'local_address':'127.0.0.1','port':5002,'process':'python'}),))
    gateway.get('/inventory/inventory')
    runtime.db.execute('UPDATE services SET verification=? WHERE id=?',(json.dumps({'state':'Protection Failed','forwarded':True,'healthy':False}),'service-inventory'))
    assert admin.get('/api/discovery/ports?port=5002').json()['listeners'][0]['security_status']=='Protection Failed'
    assert next(s for s in admin.get('/api/services').json() if s['id']=='service-inventory')['security_state']=='Protection Failed'
