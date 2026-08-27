"""Browser-origin and credentialed-CORS protections for the HTTP API."""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from .config import Settings

CSRF_HEADER_NAME = "X-CSRF-Token"
ORIGIN_ERROR = "Origin not allowed."


def configured_settings(request: Request) -> Settings:
    """Return settings installed by the application lifespan."""

    settings = getattr(request.app.state, "settings", None)
    if not isinstance(settings, Settings):
        raise RuntimeError("application settings are not configured")
    return settings


def request_origin_is_allowed(request: Request, *, require: bool = True) -> bool:
    """Compare the request Origin to the configured frontend origin exactly."""

    origin = request.headers.get("origin")
    settings = configured_settings(request)
    allowed = origin == settings.app_origin
    if require and not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ORIGIN_ERROR,
        )
    return allowed


def require_exact_origin(request: Request) -> None:
    """FastAPI dependency for state-changing browser requests."""

    request_origin_is_allowed(request)


def check_optional_origin(request: Request) -> None:
    """Reject a supplied foreign Origin while preserving non-browser callers."""

    if "origin" in request.headers:
        request_origin_is_allowed(request)


def _settings_from_scope(scope: Mapping[str, object]) -> Settings | None:
    app = scope.get("app")
    state = getattr(app, "state", None)
    settings = getattr(state, "settings", None)
    return settings if isinstance(settings, Settings) else None


class ConfiguredCORSMiddleware(BaseHTTPMiddleware):
    """Allow credentials only to the one configured frontend origin."""

    _allowed_methods = "GET, POST, OPTIONS"
    _allowed_headers = f"Content-Type, {CSRF_HEADER_NAME}"

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        origin = request.headers.get("origin")
        settings = _settings_from_scope(request.scope)
        if settings is None:
            return await call_next(request)
        allowed = origin == settings.app_origin
        requested_method = request.headers.get("access-control-request-method")

        if request.method == "OPTIONS" and requested_method is not None:
            if not allowed or requested_method.upper() not in {"GET", "POST"}:
                return Response(status_code=status.HTTP_400_BAD_REQUEST)
            response = Response(status_code=status.HTTP_204_NO_CONTENT)
            _add_cors_headers(response, settings.app_origin)
            return response

        response = await call_next(request)
        if allowed:
            _add_cors_headers(response, settings.app_origin)
        return response


def _add_cors_headers(response: Response, allowed_origin: str) -> None:
    """Attach the minimal credentialed-CORS response headers."""

    response.headers["Access-Control-Allow-Origin"] = allowed_origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = ConfiguredCORSMiddleware._allowed_methods
    response.headers["Access-Control-Allow-Headers"] = ConfiguredCORSMiddleware._allowed_headers
    response.headers["Vary"] = "Origin"


def csrf_header(request: Request) -> str | None:
    """Read the session-bound CSRF value from the custom request header."""

    value = request.headers.get(CSRF_HEADER_NAME)
    if value is None:
        return None
    return value or None


__all__ = [
    "CSRF_HEADER_NAME",
    "ConfiguredCORSMiddleware",
    "ORIGIN_ERROR",
    "check_optional_origin",
    "configured_settings",
    "csrf_header",
    "request_origin_is_allowed",
    "require_exact_origin",
]
