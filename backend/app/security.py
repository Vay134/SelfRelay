"""Browser-origin and credentialed-CORS protections for the HTTP API."""

from __future__ import annotations

import sys
from collections.abc import Mapping

from fastapi import HTTPException, Request, status
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import Settings

CSRF_HEADER_NAME = "X-CSRF-Token"
ORIGIN_ERROR = "Origin not allowed."
MAX_HTTP_REQUEST_BYTES = 64 * 1024
# Compatibility aliases for callers that describe this as a request-body limit.
MAX_HTTP_BODY_BYTES = MAX_HTTP_REQUEST_BYTES
REQUEST_BODY_TOO_LARGE_MESSAGE = "Request body too large."


class RequestBodyLimitMiddleware:
    """Reject oversized HTTP bodies before application handlers parse them."""

    def __init__(self, app: ASGIApp, max_body_bytes: int = MAX_HTTP_REQUEST_BYTES) -> None:
        if max_body_bytes <= 0:
            raise ValueError("maximum request body size must be positive")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        declared_length = _declared_body_length(headers)
        if declared_length is not None:
            if declared_length > self.max_body_bytes:
                await self._too_large(scope, receive, send)
                return
            await self.app(scope, receive, send)
            return

        if headers.get("transfer-encoding") is None:
            await self.app(scope, receive, send)
            return

        body = await self._buffer_body(receive)
        if body is None:
            await self._too_large(scope, receive, send)
            return
        await self.app(scope, _replay(body), send)

    async def _buffer_body(self, receive: Receive) -> bytes | None:
        """Read a chunked body up to the limit, returning None when it overflows."""

        chunks: list[bytes] = []
        consumed = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunk = message.get("body", b"")
            if isinstance(chunk, bytes) and chunk:
                consumed += len(chunk)
                if consumed > self.max_body_bytes:
                    return None
                chunks.append(chunk)
            if not message.get("more_body", False):
                break
        return b"".join(chunks)

    async def _too_large(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            {"detail": REQUEST_BODY_TOO_LARGE_MESSAGE},
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
        await response(scope, receive, send)


def _declared_body_length(headers: Headers) -> int | None:
    """Return the declared body size, or a rejecting size when it is unusable."""

    content_length = headers.get("content-length")
    if content_length is None:
        return None
    try:
        declared = int(content_length)
    except ValueError:
        return sys.maxsize
    return declared if declared >= 0 else sys.maxsize


def _replay(body: bytes) -> Receive:
    """Return a receive channel that replays one fully buffered request body."""

    sent = False

    async def receive() -> Message:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


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
    "MAX_HTTP_BODY_BYTES",
    "MAX_HTTP_REQUEST_BYTES",
    "ORIGIN_ERROR",
    "REQUEST_BODY_TOO_LARGE_MESSAGE",
    "RequestBodyLimitMiddleware",
    "check_optional_origin",
    "configured_settings",
    "csrf_header",
    "request_origin_is_allowed",
    "require_exact_origin",
]
