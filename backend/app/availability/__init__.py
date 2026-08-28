"""Small, safe HTTP availability boundaries for the hosted backend."""

from __future__ import annotations

import asyncio
from typing import Annotated, Protocol, cast

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from ..operator_metrics import require_operator_auth

# Keep this below the general database operation timeout. The availability
# boundary must never leave a caller waiting for a provider connection.
AVAILABILITY_DATABASE_TIMEOUT_SECONDS = 2.0
DATABASE_PROBE_QUERY = "SELECT 1"
AVAILABILITY_UNAVAILABLE_MESSAGE = "The secure transfer service is temporarily unavailable."
AVAILABILITY_AUTHORIZATION_ERROR = "Authentication required."


class _DatabaseProbe(Protocol):
    """Small database surface needed by an availability check."""

    @property
    def is_connected(self) -> bool: ...

    async def connect(self) -> None: ...

    async def fetch(self, query: str, *parameters: object) -> list[object]: ...


router = APIRouter(prefix="/availability", tags=["availability"])


def _database(request: Request) -> _DatabaseProbe | None:
    """Return the configured database boundary without exposing its internals."""

    database = getattr(request.app.state, "database", None)
    if database is None:
        return None
    return cast(_DatabaseProbe, database)


async def _database_is_available(database: _DatabaseProbe | None) -> bool:
    """Run one bounded, non-sensitive database connectivity check."""

    if database is None:
        return False

    async def check() -> bool:
        if not database.is_connected:
            await database.connect()
        await database.fetch(DATABASE_PROBE_QUERY)
        return True

    try:
        return await asyncio.wait_for(
            check(),
            timeout=AVAILABILITY_DATABASE_TIMEOUT_SECONDS,
        )
    except Exception:
        # Provider errors, malformed test doubles, and timeouts intentionally
        # have the same public result. In particular, never return exception
        # text, connection URLs, hostnames, or database diagnostics.
        return False


def _unavailable_response() -> JSONResponse:
    return JSONResponse(
        {"status": "unavailable"},
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


@router.get("/wake", response_model=None)
async def wake() -> dict[str, str]:
    """Provide a cheap public request that wakes a cold application instance."""

    return {"status": "ok"}


@router.get("/readiness", response_model=None)
async def readiness(request: Request) -> dict[str, str] | JSONResponse:
    """Report only whether the process can reach its database boundary."""

    if not await _database_is_available(_database(request)):
        return _unavailable_response()
    return {"status": "ready"}


async def require_probe_auth(request: Request) -> None:
    """Keep the availability probe behind the existing operator secret."""

    await require_operator_auth(request)


@router.get("/probe", response_model=None)
async def probe(
    request: Request,
    _authenticated: Annotated[None, Depends(require_probe_auth)],
) -> dict[str, str] | JSONResponse:
    """Run the authenticated database-backed availability probe."""

    if not await _database_is_available(_database(request)):
        return _unavailable_response()
    return {"status": "ok"}


__all__ = [
    "AVAILABILITY_AUTHORIZATION_ERROR",
    "AVAILABILITY_DATABASE_TIMEOUT_SECONDS",
    "AVAILABILITY_UNAVAILABLE_MESSAGE",
    "DATABASE_PROBE_QUERY",
    "probe",
    "readiness",
    "require_probe_auth",
    "router",
    "wake",
]
