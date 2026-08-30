"""Authenticated application-session endpoints and the future device-login seam."""

from __future__ import annotations

import hmac
from collections.abc import Awaitable
from datetime import UTC, datetime
from typing import Annotated, Protocol, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from .repositories.models import SessionRecord
from .security import (
    CSRF_HEADER_NAME,
    check_optional_origin,
    csrf_header,
    require_exact_origin,
)
from .sessions import (
    SESSION_ABSOLUTE_SECONDS,
    SESSION_COOKIE_NAME,
    CreatedSession,
    SessionService,
    hash_csrf_secret,
    hash_session_token,
)

SESSION_REQUIRED_MESSAGE = "Authentication required."
CSRF_ERROR_MESSAGE = "CSRF validation failed."
LOGOUT_MESSAGE = "Logged out."


class SessionQueryPort(Protocol):
    """Persistence operations needed by authenticated session routes."""

    async def find_by_token_hash(self, token_hash: bytes) -> SessionRecord | None: ...

    async def list_for_account(self, account_id: UUID) -> list[SessionRecord]: ...

    async def touch_last_seen(
        self,
        account_id: UUID,
        session_id: UUID,
    ) -> SessionRecord | None: ...

    async def replace_csrf_hash(
        self,
        account_id: UUID,
        session_id: UUID,
        csrf_hash: bytes,
    ) -> SessionRecord | None: ...

    async def revoke(
        self,
        account_id: UUID,
        session_id: UUID,
        reason: str = "logout",
    ) -> SessionRecord | None: ...


def set_session_cookie(response: Response, token: str) -> None:
    """Set the host-only application cookie with the documented protections."""

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_ABSOLUTE_SECONDS,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def clear_session_cookie(response: Response) -> None:
    """Expire the host-only cookie using the same security attributes."""

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


class SessionIssuer:
    """Issue a durable session after a future device-registration service succeeds."""

    def __init__(self, service: SessionService) -> None:
        self._service = service

    async def issue_for_device(
        self,
        account_id: UUID,
        device_id: UUID,
        epoch: int,
        response: Response | None = None,
        *,
        created_at: datetime | None = None,
    ) -> CreatedSession:
        """Create a session and optionally attach its cookie to an HTTP response."""

        created = await self._service.create(
            account_id,
            device_id,
            epoch,
            created_at=created_at,
        )
        if response is not None:
            set_session_cookie(response, created.token)
        return created

    async def issue(
        self,
        account_id: UUID,
        device_id: UUID,
        epoch: int,
        response: Response | None = None,
        *,
        created_at: datetime | None = None,
    ) -> CreatedSession:
        """Compatibility name for the Phase 3 device-login integration seam."""

        return await self.issue_for_device(
            account_id,
            device_id,
            epoch,
            response=response,
            created_at=created_at,
        )


class SessionAuthenticator:
    """Authenticate an opaque cookie through a repository-backed digest lookup."""

    def __init__(self, repository: SessionQueryPort) -> None:
        self._repository = repository

    async def authenticate(
        self,
        token: str | None,
        *,
        now: datetime | None = None,
    ) -> SessionRecord | None:
        """Return a currently active session, never the raw cookie value."""

        token_hash = _token_hash(token)
        if token_hash is None:
            return None
        record = await self._repository.find_by_token_hash(token_hash)
        current = datetime.now(UTC) if now is None else now
        if current.tzinfo is None:
            raise ValueError("session timestamps must be timezone-aware")
        current = current.astimezone(UTC)
        if record is None or not _is_current(record, current):
            return None

        toucher = getattr(self._repository, "touch_last_seen", None)
        if not callable(toucher):
            return record
        touch_result = toucher(record.user_id, record.id)
        touched = await cast(Awaitable[SessionRecord | None], touch_result)
        return touched if touched is not None else record


def _token_hash(token: str | None) -> bytes | None:
    if token is None or not 1 <= len(token) <= 512:
        return None
    try:
        return hash_session_token(token)
    except (UnicodeEncodeError, ValueError):
        return None


def _is_current(record: SessionRecord, now: datetime) -> bool:
    return (
        record.revoked_at is None
        and record.idle_expires_at > now
        and record.absolute_expires_at > now
    )


def _repository_from_request(request: Request) -> SessionQueryPort:
    repository = getattr(request.app.state, "session_repository", None)
    if repository is None:
        raise RuntimeError("session repository is not configured")
    return cast(SessionQueryPort, repository)


def _service_from_request(request: Request) -> SessionService:
    service = getattr(request.app.state, "session_service", None)
    if service is None:
        raise RuntimeError("session service is not configured")
    return cast(SessionService, service)


def _authenticator_from_request(request: Request) -> SessionAuthenticator:
    authenticator = getattr(request.app.state, "session_authenticator", None)
    if isinstance(authenticator, SessionAuthenticator):
        return authenticator
    authenticator = SessionAuthenticator(_repository_from_request(request))
    request.app.state.session_authenticator = authenticator
    return authenticator


async def get_authenticated_session(request: Request) -> SessionRecord:
    """FastAPI dependency that authenticates only from the secure cookie."""

    existing = getattr(request.state, "authenticated_session", None)
    if isinstance(existing, SessionRecord):
        return existing
    record = await _authenticator_from_request(request).authenticate(
        request.cookies.get(SESSION_COOKIE_NAME)
    )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=SESSION_REQUIRED_MESSAGE,
        )
    request.state.authenticated_session = record
    return record


async def require_session_csrf(
    request: Request,
    session: Annotated[SessionRecord, Depends(get_authenticated_session)],
    _origin: Annotated[None, Depends(require_exact_origin)],
) -> SessionRecord:
    """Require the exact frontend Origin and the session-bound CSRF header."""

    supplied = csrf_header(request)
    if supplied is None or not _valid_csrf_value(supplied, session.csrf_hash):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=CSRF_ERROR_MESSAGE,
        )
    return session


def _valid_csrf_value(value: str, expected_hash: bytes) -> bool:
    if not 1 <= len(value) <= 512:
        return False
    try:
        actual_hash = hash_csrf_secret(value)
    except (UnicodeEncodeError, ValueError):
        return False
    return hmac.compare_digest(actual_hash, expected_hash)


def public_session(record: SessionRecord) -> dict[str, object]:
    """Serialize only session metadata safe for the authenticated browser."""

    return {
        "session_id": str(record.id),
        "device_id": str(record.device_id),
        "created_at": record.created_at,
        "last_seen_at": record.last_seen_at,
        "idle_expires_at": record.idle_expires_at,
        "absolute_expires_at": record.absolute_expires_at,
        "revoked_at": record.revoked_at,
        "revocation_reason": record.revocation_reason,
    }


router = APIRouter(prefix="/auth", tags=["sessions"])


@router.get("/session")
@router.get("/session/current")
@router.get("/current-session")
async def current_session(
    request: Request,
    session: Annotated[SessionRecord, Depends(get_authenticated_session)],
) -> dict[str, object]:
    """Authenticate the cookie and issue a fresh session-bound CSRF value."""

    check_optional_origin(request)
    csrf_secret, updated = await _service_from_request(request).reissue_csrf(
        session.user_id,
        session.id,
    )
    public = public_session(updated)
    return {
        **public,
        "authenticated": True,
        "account_id": str(updated.user_id),
        "account_device_epoch": updated.epoch,
        "csrf_token": csrf_secret,
        "session": public,
    }


@router.post("/session/logout", dependencies=[Depends(require_session_csrf)])
@router.post("/logout", dependencies=[Depends(require_session_csrf)])
async def logout(request: Request, response: Response) -> dict[str, object]:
    """Log out the current device, revoke its sessions, and expire its cookie."""

    session = await get_authenticated_session(request)
    device_store = getattr(request.app.state, "device_repository", None)
    logout_device = getattr(device_store, "logout_with_sessions", None)
    if callable(logout_device):
        logged_out = await logout_device(session.user_id, session.device_id, "logout")
        if logged_out is None:
            await _service_from_request(request).revoke(session.user_id, session.id, "logout")
        presence_manager = getattr(request.app.state, "presence_manager", None)
        disconnect = getattr(presence_manager, "disconnect_device", None)
        if callable(disconnect):
            await disconnect(session.user_id, session.device_id)
    else:
        await _service_from_request(request).revoke(session.user_id, session.id, "logout")
    clear_session_cookie(response)
    return {"message": LOGOUT_MESSAGE, "logged_out": True}


@router.get("/sessions")
@router.get("/session/list")
async def list_sessions(
    request: Request,
    session: Annotated[SessionRecord, Depends(get_authenticated_session)],
) -> dict[str, object]:
    """List account sessions without exposing raw tokens or cryptographic hashes."""

    check_optional_origin(request)
    records = await _repository_from_request(request).list_for_account(session.user_id)
    return {"sessions": [public_session(record) for record in records]}


__all__ = [
    "CSRF_HEADER_NAME",
    "CSRF_ERROR_MESSAGE",
    "SessionAuthenticator",
    "SessionIssuer",
    "clear_session_cookie",
    "current_session",
    "get_authenticated_session",
    "list_sessions",
    "logout",
    "public_session",
    "require_session_csrf",
    "router",
    "set_session_cookie",
]
