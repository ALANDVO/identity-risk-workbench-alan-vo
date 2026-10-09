import json
import httpx
import pytest
from fastapi.testclient import TestClient
from app.main import create_app
from app.core.config import Settings, ConfigError, validate_settings
from app.core.auth import create_session
from fastapi import Response
from app.services.advice import advise
from app.domain.analysis import analyze
from test_domain import export, snapshot


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(environment='test', auth_mode='demo', cookie_secure=False, database_path=str(tmp_path/'api.db')))
    with TestClient(app) as client:
        response = client.post('/api/auth/demo')
        client.headers['X-CSRF-Token'] = response.json()['csrf_token']
        yield client


def upload(client):
    response = client.post('/api/snapshots', files={'file': ('export.json', json.dumps(export()).encode(), 'application/json')}, data={'name': 'Test evidence'})
    assert response.status_code == 201, response.text
    return response.json()['snapshot']['id']


def test_full_review_plan_and_export_workflow(client):
    id_ = upload(client)
    detail = client.get('/api/snapshots/'+id_).json()
    f = detail['analysis']['findings'][0]
    assert client.post(f'/api/snapshots/{id_}/reviews/{f["id"]}',json={'decision':'accepted','note':'Owner accepted limited risk','version':0}).status_code == 200
    actions = [{'kind':'remove_group','identity_id':'a','value':'nested'}]
    preview = client.post(f'/api/snapshots/{id_}/plans/preview',json={'actions':actions})
    assert preview.status_code == 200 and preview.json()['resolved']
    plan = client.post(f'/api/snapshots/{id_}/plans',json={'actions':actions,'title':'Separate duties'}).json()
    decision = {'state':'approved','note':'Confirmed with owner','version':1}
    assert client.post(f'/api/snapshots/{id_}/plans/{plan["id"]}/decision',json=decision).status_code == 409
    user = client.post('/api/auth/demo?identity=reviewer').json()
    client.headers['X-CSRF-Token'] = user['csrf_token']
    approved = client.post(f'/api/snapshots/{id_}/plans/{plan["id"]}/decision',json=decision)
    assert approved.status_code == 200 and approved.json()['state']=='approved'
    assert client.get(f'/api/snapshots/{id_}/export/json').json()['plans'][0]['state']=='approved'
    assert 'text/csv' in client.get(f'/api/snapshots/{id_}/export/csv').headers['content-type']
    assert client.delete(f'/api/snapshots/{id_}?version=1').status_code==403


def test_preview_does_not_store_and_replay_does_not_duplicate(client):
    data=json.dumps(export()).encode()
    assert client.post('/api/import/preview',files={'file':('e.json',data)}).status_code==200
    assert client.get('/api/snapshots').json()==[]
    first=upload(client);second=upload(client)
    assert first==second and len(client.get('/api/snapshots').json())==1


def test_csrf_and_logout_revocation(client):
    csrf=client.headers.pop('X-CSRF-Token')
    assert client.post('/api/snapshots',files={'file':('x.json',b'{}')},data={'name':'x'}).status_code==403
    client.headers['X-CSRF-Token']=csrf
    old=client.cookies.get('identity_session')
    assert client.post('/api/auth/logout').status_code==204
    client.cookies.set('identity_session',old)
    assert client.get('/api/snapshots').status_code==401


def test_viewer_cannot_mutate_or_read_audit(client):
    response=Response()
    user=create_session(client.app.state.db,client.app.state.settings,response,'reader','Reader',['viewer'])
    cookie=response.headers['set-cookie'].split(';')[0].split('=',1)[1]
    client.cookies.clear();client.cookies.set('identity_session',cookie)
    client.headers['X-CSRF-Token']=user['csrf_token']
    assert client.get('/api/snapshots').status_code==200
    assert client.get('/api/audit').status_code==403
    assert client.post('/api/import/preview',files={'file':('x.json',b'{}')}).status_code==403


def test_invalid_policy_does_not_become_server_error(client):
    response=client.post('/api/import/preview',files={'file':('e.json',json.dumps(export()).encode())},
      data={'policy':json.dumps({'toxic_pairs':[{'name':{},'left':'a:b','right':'a:c'}]})})
    assert response.status_code==422


def test_authentication_required(client):
    client.cookies.clear()
    assert client.get('/api/snapshots').status_code==401
    assert client.get('/health').json()['status']=='ok'


def test_two_app_databases_are_isolated(client,tmp_path):
    upload(client)
    other=create_app(Settings(environment='test',auth_mode='demo',cookie_secure=False,database_path=str(tmp_path/'other.db')))
    with TestClient(other) as c:
        c.post('/api/auth/demo')
        assert c.get('/api/snapshots').json()==[]


def test_oversized_import_rejected(client):
    response=client.post('/api/import/preview',files={'file':('e.json',b' '*(5*1024*1024+1))})
    assert response.status_code==413


@pytest.mark.parametrize('settings',[Settings(environment='production',auth_mode='demo'),Settings(auth_mode='demo',bind_host='0.0.0.0'),Settings(environment='production',cookie_secure=False)])
def test_unsafe_settings_rejected(settings):
    with pytest.raises(ConfigError):validate_settings(settings)


@pytest.mark.parametrize('provider',['openai','openai-compatible','anthropic','gemini','ollama'])
def test_llm_adapters_send_aggregate_counts_only(provider):
    calls=[]
    def handler(request):
        calls.append(request);body=json.loads(request.content)
        assert 'Analyst' not in request.content.decode() and 'identity_id' not in request.content.decode()
        user=body['messages'][-1]['content'];assert json.loads(user)==analyze(snapshot())['summary']
        return httpx.Response(200,json={'content':[{'type':'text','text':'Review aggregate risks.'}]} if provider=='anthropic' else {'choices':[{'message':{'content':'Review aggregate risks.'}}]})
    result=advise(analyze(snapshot()),Settings(llm_provider=provider,llm_api_key='test-only-not-a-secret'),True,httpx.MockTransport(handler))
    assert result['source']=='llm' and result['external_sent'] and len(calls)==1


def test_offline_advice_never_calls_network():
    def fail(_):raise AssertionError('Unexpected network')
    assert advise(analyze(snapshot()),Settings(),False,httpx.MockTransport(fail))['external_sent'] is False
    assert advise(analyze(snapshot()),Settings(),True,httpx.MockTransport(fail))['source']=='local'


@pytest.mark.parametrize('data',[{}, {'choices':[]}, {'choices':[{'message':{'content':None}}]}, {'choices':[{'message':{'content':''}}]}])
def test_malformed_provider_output_has_local_fallback(data):
    result=advise(analyze(snapshot()),Settings(llm_api_key='test-only-not-a-secret'),True,httpx.MockTransport(lambda _:httpx.Response(200,json=data)))
    assert result['source']=='local' and result['external_sent']


def test_provider_error_does_not_expose_response():
    result=advise(analyze(snapshot()),Settings(llm_api_key='test-only-not-a-secret'),True,httpx.MockTransport(lambda _:httpx.Response(500,text='sensitive-provider-diagnostic')))
    assert 'sensitive-provider-diagnostic' not in json.dumps(result)


@pytest.mark.parametrize('name', ['\ud800', ' padded ', 'line\nbreak'])
def test_malformed_custom_policy_labels_return_validation_error(client, name):
    response=client.post('/api/import/preview',files={'file':('e.json',json.dumps(export()).encode())},
        data={'policy':json.dumps({'toxic_pairs':[{'name':name,'left':'payments:create','right':'payments:approve'}]})})
    assert response.status_code==422
    assert response.json()['error']=='invalid_input'
