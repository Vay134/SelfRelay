"""Typed application settings loaded from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, cast
from urllib.parse import urlsplit

AppEnvironment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
AuthAdapter = Literal["supabase", "fake"]
TurnAdapter = Literal["cloudflare", "fake", "disabled"]

_DEFAULT_APP_ENV: Final[AppEnvironment] = "development"
_DEFAULT_LOG_LEVEL: Final[LogLevel] = "INFO"
_DEFAULT_AUTH_ADAPTER: Final[AuthAdapter] = "fake"
_DEFAULT_TURN_ADAPTER: Final[TurnAdapter] = "fake"
_DEFAULT_RATE_LIMIT_SECRET: Final[str] = "local-development-rate-limit-secret"

_APP_ENVIRONMENTS: Final[frozenset[str]] = frozenset({"development", "test", "production"})
_LOG_LEVELS: Final[frozenset[str]] = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_AUTH_ADAPTERS: Final[frozenset[str]] = frozenset({"supabase", "fake"})
_TURN_ADAPTERS: Final[frozenset[str]] = frozenset({"cloudflare", "fake", "disabled"})


class ConfigurationError(ValueError):
    """Raised when an environment value cannot produce valid settings."""


def _value(environ: Mapping[str, str], name: str, default: str) -> str:
    raw_value = environ.get(name)
    if raw_value is None:
        return default
    value = raw_value.strip()
    if not value:
        raise ConfigurationError(f"{name} must not be empty")
    return value


def _optional_value(environ: Mapping[str, str], name: str) -> str | None:
    raw_value = environ.get(name)
    if raw_value is None:
        return None
    value = raw_value.strip()
    if not value:
        raise ConfigurationError(f"{name} must not be empty")
    return value


def _choice(
    environ: Mapping[str, str],
    name: str,
    default: str,
    allowed: frozenset[str],
    *,
    lower: bool = False,
) -> str:
    value = _value(environ, name, default)
    normalized = value.casefold() if lower else value.upper()
    if normalized not in allowed:
        choices = ", ".join(sorted(allowed))
        raise ConfigurationError(f"{name} must be one of: {choices}")
    return normalized


def _origin(environ: Mapping[str, str], name: str) -> str:
    value = _value(environ, name, "")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError(f"{name} must be an absolute HTTP(S) origin")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError(f"{name} must not include user information")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ConfigurationError(f"{name} must contain only an HTTP(S) origin")
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(f"{name} must use a valid port") from error
    if not hostname:
        raise ConfigurationError(f"{name} must include a host")
    if port is not None and not 0 <= port <= 65535:
        raise ConfigurationError(f"{name} must use a valid port")
    return value.rstrip("/")


def _database_url(environ: Mapping[str, str]) -> str:
    value = _value(environ, "DATABASE_URL", "")
    parsed = urlsplit(value)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.netloc:
        raise ConfigurationError("DATABASE_URL must be an absolute PostgreSQL connection URL")
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError("DATABASE_URL must use a valid port") from error
    if not hostname:
        raise ConfigurationError("DATABASE_URL must include a host")
    if port is not None and not 0 <= port <= 65535:
        raise ConfigurationError("DATABASE_URL must use a valid port")
    if parsed.fragment:
        raise ConfigurationError("DATABASE_URL must not include a fragment")
    return value


def _turn_secret(environ: Mapping[str, str], name: str, *, required: bool) -> str | None:
    raw_value = environ.get(name)
    if raw_value is None:
        if required:
            raise ConfigurationError(f"{name} must be configured when TURN_ADAPTER is cloudflare")
        return None
    value = raw_value.strip()
    if not value:
        raise ConfigurationError(f"{name} must not be empty")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated runtime settings for the application."""

    app_env: AppEnvironment
    app_origin: str
    api_origin: str
    database_url: str
    log_level: LogLevel
    auth_adapter: AuthAdapter
    turn_adapter: TurnAdapter
    rate_limit_secret: str = _DEFAULT_RATE_LIMIT_SECRET
    supabase_url: str | None = None
    supabase_publishable_key: str | None = None
    availability_probe_token: str | None = None
    cloudflare_turn_key_id: str | None = None
    cloudflare_turn_api_token: str | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        """Load and validate settings from ``environ`` or the process environment."""

        source = os.environ if environ is None else environ
        app_env = _choice(
            source,
            "APP_ENV",
            _DEFAULT_APP_ENV,
            _APP_ENVIRONMENTS,
            lower=True,
        )
        log_level = _choice(
            source,
            "LOG_LEVEL",
            _DEFAULT_LOG_LEVEL,
            _LOG_LEVELS,
        )
        auth_adapter = _choice(
            source,
            "AUTH_ADAPTER",
            _DEFAULT_AUTH_ADAPTER,
            _AUTH_ADAPTERS,
            lower=True,
        )
        turn_adapter = _choice(
            source,
            "TURN_ADAPTER",
            _DEFAULT_TURN_ADAPTER,
            _TURN_ADAPTERS,
            lower=True,
        )
        rate_limit_secret = _value(source, "RATE_LIMIT_SECRET", _DEFAULT_RATE_LIMIT_SECRET)
        supabase_url = _optional_value(source, "SUPABASE_URL")
        supabase_publishable_key = _optional_value(source, "SUPABASE_PUBLISHABLE_KEY")
        availability_probe_token = _optional_value(source, "AVAILABILITY_PROBE_TOKEN")
        cloudflare_turn_key_id = _turn_secret(
            source,
            "CLOUDFLARE_TURN_KEY_ID",
            required=turn_adapter == "cloudflare",
        )
        cloudflare_turn_api_token = _turn_secret(
            source,
            "CLOUDFLARE_TURN_API_TOKEN",
            required=turn_adapter == "cloudflare",
        )
        if app_env == "production" and (auth_adapter == "fake" or turn_adapter == "fake"):
            raise ConfigurationError("fake adapters are not allowed when APP_ENV is production")
        if auth_adapter == "supabase" and (supabase_url is None or supabase_publishable_key is None):
            raise ConfigurationError("SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY must be configured when AUTH_ADAPTER is supabase")
        return cls(
            app_env=cast(AppEnvironment, app_env),
            app_origin=_origin(source, "APP_ORIGIN"),
            api_origin=_origin(source, "API_ORIGIN"),
            database_url=_database_url(source),
            log_level=cast(LogLevel, log_level),
            auth_adapter=cast(AuthAdapter, auth_adapter),
            turn_adapter=cast(TurnAdapter, turn_adapter),
            rate_limit_secret=rate_limit_secret,
            supabase_url=_origin(source, "SUPABASE_URL") if supabase_url else None,
            supabase_publishable_key=supabase_publishable_key,
            availability_probe_token=availability_probe_token,
            cloudflare_turn_key_id=cloudflare_turn_key_id,
            cloudflare_turn_api_token=cloudflare_turn_api_token,
        )


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Return validated application settings."""

    return Settings.from_env(environ)
