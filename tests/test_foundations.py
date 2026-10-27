import json
import pytest
from pydantic import ValidationError
from app.database.models import Policy, ServiceInput
from app.discovery.windows_scanner import parse_windows_output
from app.discovery.process_inspector import process_info
from app.discovery.classification import classify
from app.security.validation import validate_backend, safe_request_path, path_matches
from app.config import Settings
from app.database.db import Database
from app.gateway.rate_limiter import RateLimiter


def test_windows_parsing():
    rows = parse_windows_output(json.dumps([{'LocalAddress':'127.0.0.1','LocalPort':5001,'OwningProcess':22,'ProcessName':'python','ExecutablePath':None}, {'LocalAddress':'bad','LocalPort':'bad'}]))
    assert len(rows)==1 and rows[0]['pid']==22 and rows[0]['executable'] is None
    assert parse_windows_output('') == []
    assert len(parse_windows_output('{"LocalAddress":"::1","LocalPort":8002}'))==1


def test_process_race():
    assert process_info({'pid':'invalid'})['process']=='Unknown'
    assert process_info({'OwningProcess':10})['pid']==10


def test_classification_evidence():
    listener = {'local_address':'0.0.0.0','port':5001}
    result = classify(listener,[])
    assert result['classification']=='Unknown' and result['reachability']=='Unknown'
    assert result['security_status']=='Potentially Exposed'
    service={'id':'a','enabled':True,'backend_url':'http://127.0.0.1:5001','verification':{'forwarded':True}}
    result=classify(dict(listener,local_address='127.0.0.1'),[service])
    assert result['security_status']=='Gateway Managed'
    assert 'local processes' in result['explanation']


@pytest.mark.parametrize('url',['https://evil.example:5001','http://127.0.0.1:8002','http://127.0.0.1:8080','file:///etc/passwd','http://user:pass@127.0.0.1:5001','http://127.0.0.1:5001/x','http://169.254.169.254:8081','http://127.0.0.1:80','http://127.0.0.1:5001?x=1'])
def test_invalid_backend(url):
    with pytest.raises(ValueError):
        validate_backend(url,Settings())


def test_valid_backend():
    assert validate_backend('http://127.0.0.1:5001/',Settings())=='http://127.0.0.1:5001'


@pytest.mark.parametrize('path',['/student/%2e%2e/api','/student/%252e%252e/api','/student//evil','/student/%5cevil','/student/%00'])
def test_path_normalization(path):
    with pytest.raises(ValueError):
        safe_request_path(path)


def test_route_boundary():
    assert path_matches('/student/a','/student')
    assert not path_matches('/students/a','/student')


@pytest.mark.parametrize('kwargs',[{'limit':0},{'window':0},{'methods':['TRACE']},{'max_body':999999999},{'allowed_paths':['/../']},{'client_key_env':'literal-secret!'}])
def test_policy_validation(kwargs):
    with pytest.raises(ValidationError):
        Policy(**kwargs)


def test_persistence(tmp_path):
    path=str(tmp_path/'db.sqlite')
    first=Database(path)
    first.save_service('a',ServiceInput(name='a',backend_url='http://127.0.0.1:5001',gateway_path='/a').model_dump())
    first.close()
    second=Database(path)
    assert second.service('a')['name']=='a'
    assert second.query('PRAGMA user_version')[0]['user_version']==3
    second.close()


def test_rate_limiter_bounds():
    limiter=RateLimiter(capacity=2)
    assert limiter.check('a','ip1',1,60)[0]
    assert not limiter.check('a','ip1',1,60)[0]
    assert limiter.check('a','ip2',1,60)[0]
    assert not limiter.check('a','ip3',1,60)[0]
    assert len(limiter.clients)==2
