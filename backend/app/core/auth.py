"""OIDC authorization code + PKCE login and server-side, revocable sessions.

Tokens never enter browser storage. Identity is accepted only after verifying
an asymmetric ID-token signature, issuer, audience, lifetime and login nonce.
"""
from __future__ import annotations
import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse
import httpx
import jwt
from fastapi import APIRouter, Request, Response
from typing import Literal
from fastapi.responses import RedirectResponse
from .config import Settings
from .db import Database, utcnow
from .errors import AppError

COOKIE = 'identity_session'
STATE_COOKIE = 'identity_login'
ROLES = {'viewer', 'reviewer', 'admin'}
router = APIRouter(prefix='/api/auth', tags=['Authentication'])


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def require_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE, '')
    row = request.app.state.db.query_one('SELECT * FROM sessions WHERE id=?', (digest(token),)) if token else None
    if row is None or datetime.fromisoformat(row['expires_at']) <= datetime.now(timezone.utc):
        raise AppError(401, 'authentication_required', 'Sign in to continue')
    user = dict(row); user['roles'] = json.loads(user['roles'])
    if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
        supplied = request.headers.get('X-CSRF-Token', '')
        if not secrets.compare_digest(supplied, user['csrf_token']):
            raise AppError(403, 'csrf_failed', 'Missing or invalid CSRF token')
    return user


def authorize(request: Request, role: str = 'viewer') -> dict:
    user = require_user(request)
    roles = set(user['roles'])
    if 'admin' not in roles and role not in roles and not (role == 'viewer' and 'reviewer' in roles):
        raise AppError(403, 'forbidden', 'Your account does not have permission for this operation')
    return user


def create_session(db: Database, settings: Settings, response: Response, subject: str,
                   username: str, roles: list[str]) -> dict:
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    roles = sorted(set(roles) & ROLES) or ['viewer']
    now = datetime.now(timezone.utc)
    with db.transaction() as conn:
        conn.execute('DELETE FROM sessions WHERE expires_at <= ?', (now.isoformat(),))
        conn.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?,?)',
                     (digest(token), subject, username, json.dumps(roles), csrf,
                      (now + timedelta(seconds=settings.session_ttl_seconds)).isoformat(), utcnow()))
    response.set_cookie(COOKIE, token, max_age=settings.session_ttl_seconds,
                        secure=settings.cookie_secure, httponly=True, samesite='lax', path='/')
    return {'subject': subject, 'username': username, 'roles': roles, 'csrf_token': csrf}


class OIDCClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        self.settings = settings
        self.transport = transport

    def fetch(self, method: str, url: str, **kwargs) -> dict:
        scheme = urlparse(url).scheme
        if scheme not in {'http', 'https'} or (self.settings.is_production and scheme != 'https'):
            raise AppError(503, 'oidc_configuration', 'Identity provider endpoints must use HTTPS in production')
        try:
            with httpx.Client(timeout=10, transport=self.transport, follow_redirects=False, trust_env=False) as client:
                response = client.request(method, url, **kwargs)
                response.raise_for_status()
                value = response.json()
                if not isinstance(value, dict):raise ValueError('Expected an object')
                return value
        except (httpx.HTTPError, ValueError) as exc:
            raise AppError(503, 'identity_provider_unavailable', 'Identity provider request failed') from exc

    def discovery(self) -> dict:
        url = self.settings.oidc_discovery_url
        suffix = '/.well-known/openid-configuration'
        if not url.endswith(suffix):
            raise AppError(503, 'oidc_configuration', 'Use the issuer discovery URL')
        data = self.fetch('GET', url)
        if data.get('issuer') != url[:-len(suffix)]:
            raise AppError(503, 'oidc_configuration', 'Discovery issuer does not match configured issuer')
        if not all(isinstance(data.get(k), str) for k in ('authorization_endpoint', 'token_endpoint', 'jwks_uri')):
            raise AppError(503, 'oidc_configuration', 'Incomplete identity provider discovery')
        for key in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
            if self.settings.is_production and urlparse(data[key]).scheme != 'https':
                raise AppError(503, 'oidc_configuration', 'Identity provider endpoints require HTTPS')
        return data

    def exchange(self, code: str, nonce: str, verifier: str) -> dict:
        data = self.discovery()
        body = {'grant_type': 'authorization_code', 'code': code,
                'redirect_uri': self.settings.oidc_redirect_uri,
                'client_id': self.settings.oidc_client_id, 'code_verifier': verifier}
        if self.settings.oidc_client_secret:body['client_secret'] = self.settings.oidc_client_secret
        tokens = self.fetch('POST', data['token_endpoint'], data=body)
        try:
            token = tokens['id_token']; header = jwt.get_unverified_header(token)
            algorithm = header.get('alg')
            if algorithm not in {'RS256', 'ES256'}:raise ValueError('Disallowed signing algorithm')
            keys = self.fetch('GET', data['jwks_uri']).get('keys', [])
            candidates = [k for k in keys if k.get('kid') == header.get('kid') and
                          k.get('use', 'sig') == 'sig' and k.get('alg', algorithm) == algorithm]
            if len(candidates) != 1:raise ValueError('Ambiguous or missing signing key')
            key = jwt.PyJWK.from_dict(candidates[0], algorithm=algorithm).key
            claims = jwt.decode(token, key, algorithms=[algorithm], audience=self.settings.oidc_client_id,
                                issuer=data['issuer'], options={'require': ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce']})
            if not isinstance(claims['nonce'], str) or not secrets.compare_digest(claims['nonce'], nonce):
                raise ValueError('Invalid nonce')
            audiences = claims['aud'] if isinstance(claims['aud'], list) else [claims['aud']]
            if (len(audiences) > 1 or 'azp' in claims) and claims.get('azp') != self.settings.oidc_client_id:
                raise ValueError('Invalid authorized party')
            return claims
        except (KeyError, ValueError, TypeError, jwt.PyJWTError) as exc:
            raise AppError(401, 'invalid_identity', 'Identity token validation failed') from exc


@router.get('/mode')
def mode(request: Request):
    return {'mode': request.app.state.settings.auth_mode}


@router.post('/demo')
def demo(request: Request, response: Response, identity: Literal["analyst", "reviewer", "admin"] = "admin"):
    settings = request.app.state.settings
    if settings.auth_mode != 'demo' or settings.is_production:
        raise AppError(404, 'not_found', 'Demo login is disabled')
    if settings.environment != 'test' and (not request.client or request.client.host not in {'127.0.0.1', '::1'}):
        raise AppError(403, 'local_only', 'Demo login is restricted to loopback clients')
    if request.headers.get('Origin') not in {None, settings.frontend_url}:
        raise AppError(403, 'origin_failed', 'Untrusted login origin')
    return create_session(request.app.state.db, settings, response, 'local-' + identity, 'Local ' + identity, ['admin'] if identity == 'admin' else ['reviewer'])


@router.get('/login')
def login(request: Request):
    settings = request.app.state.settings
    if settings.auth_mode != 'oidc':raise AppError(400, 'oidc_disabled', 'OIDC login is disabled')
    data = request.app.state.oidc.discovery()
    state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    with request.app.state.db.transaction() as conn:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec='seconds')
        conn.execute('DELETE FROM login_states WHERE created_at < ?', (cutoff,))
        conn.execute('INSERT INTO login_states VALUES(?,?,?,?)', (state, nonce, verifier, utcnow()))
    response = RedirectResponse(data['authorization_endpoint']+'?'+urlencode({
        'client_id': settings.oidc_client_id, 'redirect_uri': settings.oidc_redirect_uri,
        'response_type': 'code', 'scope': 'openid profile email', 'state': state,
        'nonce': nonce, 'code_challenge': challenge, 'code_challenge_method': 'S256'}))
    response.set_cookie(STATE_COOKIE, state, max_age=600, secure=settings.cookie_secure,
                        httponly=True, samesite='lax', path='/api/auth')
    return response


@router.get('/callback')
def callback(request: Request, state: str, code: str):
    if not state or not secrets.compare_digest(request.cookies.get(STATE_COOKIE, ''), state):
        raise AppError(401, 'invalid_login_state', 'Login state does not match this browser')
    db, settings = request.app.state.db, request.app.state.settings
    with db.transaction() as conn:
        row = conn.execute('SELECT * FROM login_states WHERE state=?', (state,)).fetchone()
        conn.execute('DELETE FROM login_states WHERE state=?', (state,))
    if row is None or datetime.now(timezone.utc) - datetime.fromisoformat(row['created_at']) > timedelta(minutes=10):
        raise AppError(401, 'invalid_login_state', 'Login expired or was already used')
    claims = request.app.state.oidc.exchange(code, row['nonce'], row['code_verifier'])
    roles = claims
    for part in settings.oidc_role_claim.split('.'):
        roles = roles.get(part, {}) if isinstance(roles, dict) else {}
    if not isinstance(roles, list):roles = []
    response = RedirectResponse(settings.frontend_url, status_code=303)
    response.delete_cookie(STATE_COOKIE, path='/api/auth')
    create_session(db, settings, response, claims['sub'], claims.get('preferred_username') if isinstance(claims.get('preferred_username'), str) else claims['sub'],
                   [r for r in roles if isinstance(r, str)])
    return response


@router.get('/me')
def me(request: Request):
    user = require_user(request)
    return {k: user[k] for k in ['subject', 'username', 'roles', 'csrf_token']}


@router.post('/logout', status_code=204)
def logout(request: Request, response: Response):
    user = require_user(request)
    with request.app.state.db.transaction() as conn:conn.execute('DELETE FROM sessions WHERE id=?', (user['id'],))
    response.delete_cookie(COOKIE, path='/')
