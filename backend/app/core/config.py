"""Runtime configuration loaded from environment variables.

All settings are read once per application instance through :func:`load_settings`
so tests can construct isolated applications with explicit overrides.
"""
from __future__ import annotations

import os
import math
from urllib.parse import urlsplit
from dataclasses import dataclass, field, replace
from pathlib import Path

VALID_AUTH_MODES = {"oidc", "demo"}
VALID_ENVIRONMENTS = {"development", "test", "production"}


class ConfigError(RuntimeError):
    """Raised when the operator supplied an unsafe or inconsistent configuration."""


@dataclass(frozen=True)
class Settings:
    environment: str = "development"
    database_path: str = "data/identity-risk.db"
    auth_mode: str = "oidc"
    bind_host: str = "127.0.0.1"
    oidc_discovery_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://127.0.0.1:8000/api/auth/callback"
    oidc_role_claim: str = "realm_access.roles"
    frontend_url: str = "http://127.0.0.1:5173"
    session_ttl_seconds: int = 8 * 3600
    cookie_secure: bool = True
    max_upload_bytes: int = 5 * 1024 * 1024
    llm_provider: str = "openai-compatible"
    llm_model: str = ""
    llm_base_url: str = ""
    llm_api_key: str = field(default="", repr=False)
    llm_timeout_seconds: float = 30.0

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def with_overrides(self, **kwargs: object) -> "Settings":
        return replace(self, **kwargs)  # type: ignore[arg-type]


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_settings() -> Settings:
    env = os.environ
    return Settings(
        environment=env.get("APP_ENV", "development"),
        database_path=env.get("DATABASE_PATH", "data/identity-risk.db"),
        auth_mode=env.get("AUTH_MODE", "oidc"),
        bind_host=env.get("BIND_HOST", "127.0.0.1"),
        oidc_discovery_url=env.get("OIDC_DISCOVERY_URL", ""),
        oidc_client_id=env.get("OIDC_CLIENT_ID", ""),
        oidc_client_secret=env.get("OIDC_CLIENT_SECRET", ""),
        oidc_redirect_uri=env.get("OIDC_REDIRECT_URI", "http://127.0.0.1:8000/api/auth/callback"),
        oidc_role_claim=env.get("OIDC_ROLE_CLAIM", "realm_access.roles"),
        frontend_url=env.get("FRONTEND_URL", "http://127.0.0.1:5173"),
        session_ttl_seconds=int(env.get("SESSION_TTL_SECONDS", str(8 * 3600))),
        cookie_secure=_bool(env.get("COOKIE_SECURE"), True),
        max_upload_bytes=int(env.get("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024))),
        llm_provider=env.get("LLM_PROVIDER", "openai-compatible"),
        llm_model=env.get("LLM_MODEL", ""),
        llm_base_url=env.get("LLM_BASE_URL", ""),
        llm_api_key=env.get("LLM_API_KEY", ""),
        llm_timeout_seconds=float(env.get("LLM_TIMEOUT_SECONDS", "30")),
    )


def validate_settings(settings: Settings) -> None:
    """Refuse unsafe combinations before the application starts serving."""
    if settings.environment not in VALID_ENVIRONMENTS:
        raise ConfigError(f"APP_ENV must be one of {sorted(VALID_ENVIRONMENTS)}")
    if settings.auth_mode not in VALID_AUTH_MODES:
        raise ConfigError(f"AUTH_MODE must be one of {sorted(VALID_AUTH_MODES)}")
    if settings.auth_mode == "demo":
        if settings.is_production:
            raise ConfigError("AUTH_MODE=demo is refused when APP_ENV=production")
        if settings.bind_host not in {"127.0.0.1", "localhost", "::1"}:
            raise ConfigError("Demo mode may only bind to localhost")
    if settings.auth_mode == "oidc" and settings.environment != "test":
        missing = [
            name
            for name, value in (
                ("OIDC_DISCOVERY_URL", settings.oidc_discovery_url),
                ("OIDC_CLIENT_ID", settings.oidc_client_id),
            )
            if not value
        ]
        if missing:
            raise ConfigError(
                "OIDC mode requires " + ", ".join(missing)
                + "; set AUTH_MODE=demo explicitly for local-only demo use"
            )
    if settings.is_production and not settings.cookie_secure:
        raise ConfigError("COOKIE_SECURE must be enabled in production")
    for name in ('session_ttl_seconds', 'max_upload_bytes', 'llm_timeout_seconds'):
        value = getattr(settings, name)
        if not math.isfinite(value) or value <= 0:
            raise ConfigError(f'{name} must be finite and positive')
    for name in ('frontend_url', 'oidc_redirect_uri', 'oidc_discovery_url'):
        value = getattr(settings, name)
        if not value and name == 'oidc_discovery_url':
            continue
        url = urlsplit(value)
        if (url.scheme not in {'http', 'https'} or not url.hostname
                or url.username or url.password or url.fragment
                or (settings.is_production and url.scheme != 'https')):
            raise ConfigError(f'{name} must be an absolute HTTP URL without credentials or fragment; production requires HTTPS')
        if name == 'frontend_url' and (url.path not in {'', '/'} or url.query):
            raise ConfigError('frontend_url must be an origin without a path or query')


def ensure_db_dir(path: str) -> None:
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
