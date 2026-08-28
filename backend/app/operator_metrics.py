"""Authenticated operator telemetry for the running process."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from .presence import PresenceManager

OPERATOR_METRICS_PATH = "/internal/metrics"
OPERATOR_AUTHORIZATION_ERROR = "Authentication required."


def _presence_manager(request: Request) -> PresenceManager:
    manager = getattr(request.app.state, "presence_manager", None)
    if not isinstance(manager, PresenceManager):
        raise RuntimeError("presence manager is not configured")
    return manager


def _operator_token(request: Request) -> str | None:
    settings = getattr(request.app.state, "settings", None)
    token = getattr(settings, "availability_probe_token", None)
    return token if isinstance(token, str) else None


def _supplied_bearer_token(request: Request) -> str | None:
    authorizations = request.headers.getlist("authorization")
    if len(authorizations) != 1:
        return None
    authorization = authorizations[0]
    scheme, separator, token = authorization.partition(" ")
    if scheme.casefold() != "bearer" or not separator or not token or " " in token:
        return None
    return token


def _tokens_match(expected: str | None, supplied: str | None) -> bool:
    if expected is None or supplied is None:
        return False
    try:
        return hmac.compare_digest(expected.encode("utf-8"), supplied.encode("utf-8"))
    except UnicodeEncodeError:
        return False


async def require_operator_auth(request: Request) -> None:
    """Require the separately configured operator bearer token."""

    if not _tokens_match(_operator_token(request), _supplied_bearer_token(request)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=OPERATOR_AUTHORIZATION_ERROR,
        )


router = APIRouter(prefix="/internal", tags=["operator"])


@router.get("/metrics")
async def resource_metrics(
    _operator: Annotated[None, Depends(require_operator_auth)],
    request: Request,
) -> dict[str, int]:
    """Return only coarse process resource gauges to an authenticated operator."""

    return await _presence_manager(request).resource_snapshot()


__all__ = [
    "OPERATOR_AUTHORIZATION_ERROR",
    "OPERATOR_METRICS_PATH",
    "require_operator_auth",
    "resource_metrics",
    "router",
]
