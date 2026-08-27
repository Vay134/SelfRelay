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
TurnAdapter = Literal["cloudflare", "fake"]

_DEFAULT_APP_ENV: Final[AppEnvironment] = "development"
_DEFAULT_LOG_LEVEL: Final[LogLevel] = "INFO"
_DEFAULT_AUTH_ADAPTER: Final[AuthAdapter] = "fake"
_DEFAULT_TURN_ADAPTER: Final[TurnAdapter] = "fake"

_APP_ENVIRONMENTS: Final[frozenset[str]] = frozenset(
    {"development", "test", "production"}
)
_LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)
_AUTH_ADAPTERS: Final[frozenset[str]] = frozenset({"supabase", "fake"})
_TURN_ADAPTERS: Final[frozenset[str]] = frozenset({"cloudflare", "fake"})


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


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated runtime settings for the application."""

    app_env: AppEnvironment
    app_origin: str
    api_origin: str
    log_level: LogLevel
    auth_adapter: AuthAdapter
    turn_adapter: TurnAdapter

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
        if app_env == "production" and (
            auth_adapter == "fake" or turn_adapter == "fake"
        ):
            raise ConfigurationError(
                "fake adapters are not allowed when APP_ENV is production"
            )
        return cls(
            app_env=cast(AppEnvironment, app_env),
            app_origin=_origin(source, "APP_ORIGIN"),
            api_origin=_origin(source, "API_ORIGIN"),
            log_level=cast(LogLevel, log_level),
            auth_adapter=cast(AuthAdapter, auth_adapter),
            turn_adapter=cast(TurnAdapter, turn_adapter),
        )


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Return validated application settings."""

    return Settings.from_env(environ)
