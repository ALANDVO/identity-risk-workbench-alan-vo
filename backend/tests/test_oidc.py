import json,time
from urllib.parse import parse_qs,urlparse
import httpx,jwt,pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from app.main import create_app
from app.core.config import Settings
from app.core.auth import OIDCClient, STATE_COOKIE
from app.core.errors import AppError

ISSUER='https://identity.example/realms/observatory'
@pytest.fixture
def oidc(tmp_path):
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()));jwk.update(kid='qa-key',use='sig',alg='RS256')
    settings=Settings(environment='test',database_path=str(tmp_path/'oidc.db'),cookie_secure=False,oidc_client_id='observatory',oidc_discovery_url=ISSUER+'/.well-known/openid-configuration')
    claims={'sub':'u1','iss':ISSUER,'aud':'observatory','iat':int(time.time()),'exp':int(time.time())+120,'nonce':'expected','realm_access':{'roles':['reviewer']}}
    calls=[]
    def handler(request):
        calls.append(request)
        if request.url.path.endswith('openid-configuration'):
            return httpx.Response(200,json={'issuer':ISSUER,'authorization_endpoint':ISSUER+'/authorize','token_endpoint':ISSUER+'/token','jwks_uri':ISSUER+'/keys'})
        if request.url.path.endswith('/token'):
            return httpx.Response(200,json={'id_token':jwt.encode(claims,private,algorithm='RS256',headers={'kid':'qa-key'})})
        if request.url.path.endswith('/keys'):return httpx.Response(200,json={'keys':[jwk]})
        return httpx.Response(404)
    return settings,claims,httpx.MockTransport(handler),calls


def test_valid_signed_identity(oidc):
    settings,claims,transport,calls=oidc
    assert OIDCClient(settings,transport).exchange('code','expected','verifier')['sub']=='u1'
    assert 'code_verifier=verifier' in next(r for r in calls if r.method=='POST').content.decode()


@pytest.mark.parametrize('field,value',[('iss','https://wrong.example'),('aud','wrong-client'),('nonce','wrong-nonce'),('exp',1),('iat',9999999999),('azp','another-client'),('aud',['observatory','another-client'])])
def test_invalid_identity_claims_rejected(oidc,field,value):
    settings,claims,transport,_=oidc;claims[field]=value
    with pytest.raises(AppError,match='Identity token validation failed'):
        OIDCClient(settings,transport).exchange('code','expected','verifier')


def test_browser_oidc_flow_uses_pkce_and_consumes_state(oidc):
    settings,claims,transport,calls=oidc
    with TestClient(create_app(settings,transport)) as client:
        response=client.get('/api/auth/login',follow_redirects=False)
        query=parse_qs(urlparse(response.headers['location']).query)
        assert query['code_challenge_method']==['S256']
        assert len(query['code_challenge'][0])==43
        claims['nonce']=query['nonce'][0]
        state=query['state'][0]
        response=client.get('/api/auth/callback',params={'state':state,'code':'code'},follow_redirects=False)
        assert response.status_code==303,response.text
        assert client.get('/api/auth/me').json()['roles']==['reviewer']
        client.cookies.set(STATE_COOKIE,state,path='/api/auth')
        assert client.get('/api/auth/callback',params={'state':state,'code':'code'}).status_code==401
        assert len([r for r in calls if r.method=='POST'])==1


def test_callback_is_bound_to_initiating_browser(oidc):
    settings,claims,transport,_=oidc
    with TestClient(create_app(settings,transport)) as client:
        response=client.get('/api/auth/login',follow_redirects=False)
        state=parse_qs(urlparse(response.headers['location']).query)['state'][0]
        client.cookies.clear()
        assert client.get('/api/auth/callback',params={'state':state,'code':'code'}).status_code==401
