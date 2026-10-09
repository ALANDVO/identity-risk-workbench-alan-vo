"""Authenticated identity review API. Every mutation uses role and CSRF checks."""
from contextlib import asynccontextmanager
from dataclasses import asdict
import json
import sqlite3
import time
from fastapi import FastAPI, Request, UploadFile, File, Form, Query
from fastapi.exceptions import RequestValidationError
from starlette.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from .core.config import Settings, load_settings, validate_settings, ensure_db_dir
from .core.db import Database
from .core.errors import AppError
from .core.auth import router as auth_router, authorize, OIDCClient
from .domain.imports import ImportFailure, load_snapshot, MAX_BYTES
from .domain.analysis import analyze
from .domain.models import Policy
from .domain.policy import parse_policy
from .services.catalog import Catalog, Conflict, MissingRecord
from .services.advice import advise

VERSION = '1.0.0'


def create_app(settings: Settings | None = None, oidc_transport=None, llm_transport=None):
    settings = settings or load_settings()
    validate_settings(settings)
    ensure_db_dir(settings.database_path)
    catalog = Catalog(settings.database_path)
    db = Database(settings.database_path)

    @asynccontextmanager
    async def lifespan(app):
        yield
        db.close()

    app = FastAPI(title='Identity Risk Workbench', version=VERSION, lifespan=lifespan,
                  description='Evidence-driven identity review and non-executing remediation planning.')
    app.state.settings = settings
    app.state.catalog = catalog
    app.state.db = db
    app.state.oidc = OIDCClient(settings, oidc_transport)
    app.state.llm_last = {}
    app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_url], allow_credentials=True,
                       allow_methods=['GET', 'POST', 'DELETE'], allow_headers=['Content-Type', 'X-CSRF-Token'])
    app.include_router(auth_router)

    @app.middleware('http')
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        return response

    @app.exception_handler(AppError)
    async def app_error(_, exc):
        return JSONResponse({'error': exc.code, 'detail': exc.message}, status_code=exc.status)

    @app.exception_handler(ValueError)
    async def input_error(_, exc):
        status = 409 if isinstance(exc, Conflict) else 422
        return JSONResponse({'error': 'conflict' if status == 409 else 'invalid_input', 'detail': str(exc)}, status_code=status)

    @app.exception_handler(MissingRecord)
    async def missing_error(_, exc):
        return JSONResponse({'error': 'not_found', 'detail': str(exc)}, status_code=404)

    @app.exception_handler(RequestValidationError)
    async def schema_error(_, exc):
        # Validation errors omit raw request inputs, which can contain identity information.
        return JSONResponse({'error': 'invalid_request', 'detail': 'Request fields or parameter types are invalid'}, status_code=422)

    @app.exception_handler(sqlite3.OperationalError)
    async def database_error(_, exc):
        return JSONResponse({'error': 'storage_unavailable', 'detail': 'Storage is temporarily unavailable'}, status_code=503)

    async def body(request, allowed, required=()):
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 65536: raise AppError(413, 'body_too_large', 'JSON request exceeds 64 KiB')
        try: data = json.loads(raw)
        except (ValueError, UnicodeError): raise ValueError('Valid JSON object required') from None
        if not isinstance(data, dict) or set(data) - set(allowed) or set(required) - set(data):
            raise ValueError('Unexpected or missing request fields')
        return data

    async def uploaded(file):
        raw = await file.read(min(settings.max_upload_bytes, MAX_BYTES) + 1)
        await file.close()
        if len(raw) > min(settings.max_upload_bytes, MAX_BYTES):
            raise AppError(413, 'upload_too_large', 'Identity export exceeds configured upload limit')
        return raw

    @app.get('/health')
    def health(): return {'status': 'ok', 'version': VERSION}

    @app.get('/api/evaluation')
    def evaluation(request: Request):
        authorize(request)
        from .services.evaluation import evaluate
        return evaluate()

    @app.get('/api/policy')
    def policy(request: Request):
        authorize(request)
        return asdict(Policy())

    @app.get('/api/snapshots')
    def snapshots(request: Request):
        authorize(request)
        return catalog.list_snapshots()

    @app.post('/api/import/preview')
    async def import_preview(request: Request, file: UploadFile = File(...), policy: str = Form('{}')):
        authorize(request, 'reviewer')
        result = analyze(load_snapshot(await uploaded(file)), parse_policy(json.loads(policy)))
        return result

    @app.post('/api/snapshots', status_code=201)
    async def import_snapshot(request: Request, file: UploadFile = File(...), name: str = Form(...), policy: str = Form('{}')):
        user = authorize(request, 'reviewer')
        return catalog.import_snapshot(await uploaded(file), name, user['subject'], json.loads(policy))

    @app.get('/api/snapshots/{id_}')
    def detail(id_: str, request: Request):
        authorize(request)
        return catalog.detail(id_)

    @app.post('/api/snapshots/{id_}/reviews/{finding_id}')
    async def review(id_: str, finding_id: str, request: Request):
        user = authorize(request, 'reviewer')
        data = await body(request, {'decision', 'note', 'version'}, {'decision', 'note', 'version'})
        return catalog.decide_finding(id_, finding_id, data['decision'], data['note'], data['version'], user['subject'])

    @app.post('/api/snapshots/{id_}/plans/preview')
    async def plan_preview(id_: str, request: Request):
        authorize(request, 'reviewer')
        data = await body(request, {'actions'}, {'actions'})
        return catalog.preview_plan(id_, data['actions'])

    @app.post('/api/snapshots/{id_}/plans', status_code=201)
    async def create_plan(id_: str, request: Request):
        user = authorize(request, 'reviewer')
        data = await body(request, {'title', 'actions'}, {'title', 'actions'})
        return catalog.create_plan(id_, data['title'], data['actions'], user['subject'])

    @app.post('/api/snapshots/{id_}/plans/{plan_id}/decision')
    async def decide_plan(id_: str, plan_id: str, request: Request):
        user = authorize(request, 'reviewer')
        data = await body(request, {'state', 'note', 'version'}, {'state', 'note', 'version'})
        return catalog.decide_plan(id_, plan_id, data['state'], data['note'], data['version'], user['subject'])

    @app.post('/api/snapshots/{id_}/advice')
    async def advice(id_: str, request: Request):
        user = authorize(request, 'reviewer')
        data = await body(request, {'external'})
        external = data.get('external', False)
        if type(external) is not bool: raise ValueError('external must be a boolean')
        if external:
            now = time.monotonic()
            if now - app.state.llm_last.get(user['subject'], -1000) < 30:
                raise AppError(429, 'rate_limited', 'Wait 30 seconds between external advice requests')
            app.state.llm_last = {k: v for k, v in app.state.llm_last.items() if now - v < 30}
            app.state.llm_last[user['subject']] = now
        result = await run_in_threadpool(advise, catalog.detail(id_)['analysis'], settings, external, llm_transport)
        with catalog.connect(write=True) as conn:
            catalog.audit(conn, user['subject'], 'advice_requested', id_, {'source': result['source'], 'external_sent': result['external_sent']})
        return result

    @app.delete('/api/snapshots/{id_}', status_code=204)
    def delete(id_: str, request: Request, version: int = Query(..., ge=1)):
        user = authorize(request, 'admin')
        catalog.delete_snapshot(id_, version, user['subject'])
        return Response(status_code=204)

    @app.get('/api/snapshots/{id_}/export/{format_}')
    def export(id_: str, format_: str, request: Request):
        authorize(request)
        if format_ not in ('csv', 'json'): raise AppError(404, 'not_found', 'Export format not supported')
        text = catalog.export_csv(id_) if format_ == 'csv' else catalog.export_json(id_)
        return Response(text, media_type='text/csv' if format_ == 'csv' else 'application/json',
                        headers={'Content-Disposition': f'attachment; filename="identity-review.{format_}"'})

    @app.get('/api/audit')
    def audit(request: Request, limit: int = Query(100, ge=1, le=500), before: int | None = Query(None, ge=1)):
        authorize(request, 'admin')
        return catalog.audit_log(limit, before)

    return app
