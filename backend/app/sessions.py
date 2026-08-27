"""Opaque application-session primitives for the device-authenticated API."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from .repositories.models import SessionRecord

SESSION_TOKEN_BYTES = 32
CSRF_SECRET_BYTES = 32
SESSION_IDLE_LIFETIME = timedelta(days=30)
SESSION_ABSOLUTE_LIFETIME = timedelta(days=90)
SESSION_COOKIE_NAME = "__Host-session"
SESSION_IDLE_SECONDS = int(SESSION_IDLE_LIFETIME.total_seconds())
SESSION_ABSOLUTE_SECONDS = int(SESSION_ABSOLUTE_LIFETIME.total_seconds())


class SessionRepositoryPort(Protocol):
    """Persistence methods needed by the session service."""

    async def create(
        self,
        account_id: UUID,
        device_id: UUID,
        token_hash: bytes,
        csrf_hash: bytes,
        epoch: int,
        idle_expires_at: datetime,
        absolute_expires_at: datetime,
    ) -> SessionRecord: ...

    async def revoke(
        self,
        account_id: UUID,
        session_id: UUID,
        reason: str = "logout",
    ) -> SessionRecord | None: ...


@dataclass(frozen=True, slots=True)
class SessionSecrets:
    """Raw values returned once to the caller and never persisted."""

    token: str
    csrf_secret: str
    token_hash: bytes
    csrf_hash: bytes

    @property
    def session_token(self) -> str:
        """Compatibility name for callers that call the cookie value a session token."""

        return self.token

    @property
    def csrf_token(self) -> str:
        """Compatibility name for callers that call the CSRF secret a token."""

        return self.csrf_secret


@dataclass(frozen=True, slots=True)
class CreatedSession:
    """A persisted session together with its one-time raw secrets."""

    record: SessionRecord
    secrets: SessionSecrets

    @property
    def token(self) -> str:
        """Return the raw opaque cookie value."""

        return self.secrets.token

    @property
    def csrf_secret(self) -> str:
        """Return the raw session-bound CSRF value."""

        return self.secrets.csrf_secret


def _encode_opaque(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def new_opaque_token(byte_length: int = SESSION_TOKEN_BYTES) -> str:
    """Create an unpadded base64url token with at least 256 bits of entropy."""

    if byte_length < SESSION_TOKEN_BYTES:
        raise ValueError("opaque tokens must contain at least 256 bits")
    return _encode_opaque(secrets.token_bytes(byte_length))


def hash_secret(value: str | bytes) -> bytes:
    """Hash one raw secret for storage or constant-time lookup."""

    raw = value.encode("ascii") if isinstance(value, str) else bytes(value)
    return hashlib.sha256(raw).digest()


def hash_session_token(token: str) -> bytes:
    """Return the SHA-256 digest stored for a session cookie."""

    return hash_secret(token)


def hash_csrf_secret(csrf_secret: str) -> bytes:
    """Return the SHA-256 digest stored for a session-bound CSRF secret."""

    return hash_secret(csrf_secret)


def generate_session_token() -> str:
    """Create one raw session-cookie value."""

    return new_opaque_token(SESSION_TOKEN_BYTES)


def generate_csrf_secret() -> str:
    """Create one raw session-bound CSRF value."""

    return new_opaque_token(CSRF_SECRET_BYTES)


hash_token = hash_session_token
hash_csrf = hash_csrf_secret


def _utc_now(value: datetime | None) -> datetime:
    current = datetime.now(UTC) if value is None else value
    if current.tzinfo is None:
        raise ValueError("session timestamps must be timezone-aware")
    return current.astimezone(UTC)


def _session_secrets() -> SessionSecrets:
    token = generate_session_token()
    csrf_secret = generate_csrf_secret()
    return SessionSecrets(
        token=token,
        csrf_secret=csrf_secret,
        token_hash=hash_session_token(token),
        csrf_hash=hash_csrf_secret(csrf_secret),
    )


def session_expiry(created_at: datetime) -> tuple[datetime, datetime]:
    """Return idle and absolute expiry timestamps for a new session."""

    issued_at = _utc_now(created_at)
    return (
        issued_at + SESSION_IDLE_LIFETIME,
        issued_at + SESSION_ABSOLUTE_LIFETIME,
    )


class SessionService:
    """Create, rotate, and revoke durable sessions after device registration."""

    def __init__(self, repository: SessionRepositoryPort) -> None:
        self._repository = repository

    async def create(
        self,
        account_id: UUID,
        device_id: UUID,
        epoch: int,
        *,
        created_at: datetime | None = None,
        absolute_expires_at: datetime | None = None,
    ) -> CreatedSession:
        """Create a session bound to an account-owned device."""

        if not isinstance(device_id, UUID):
            raise ValueError("a session requires a device identifier")
        issued_at = _utc_now(created_at)
        idle_expires_at, default_absolute = session_expiry(issued_at)
        absolute_expiry = (
            default_absolute if absolute_expires_at is None else _utc_now(absolute_expires_at)
        )
        if absolute_expiry <= issued_at:
            raise ValueError("session absolute expiry must be in the future")
        idle_expires_at = min(idle_expires_at, absolute_expiry)
        if idle_expires_at <= issued_at:
            raise ValueError("session idle expiry must be in the future")

        secrets_for_session = _session_secrets()
        record = await self._repository.create(
            account_id,
            device_id,
            secrets_for_session.token_hash,
            secrets_for_session.csrf_hash,
            epoch,
            idle_expires_at,
            absolute_expiry,
        )
        return CreatedSession(record=record, secrets=secrets_for_session)

    async def rotate(
        self,
        account_id: UUID,
        previous: SessionRecord,
        *,
        now: datetime | None = None,
    ) -> CreatedSession:
        """Revoke one session and issue a replacement with its absolute deadline."""

        issued_at = _utc_now(now)
        if previous.absolute_expires_at <= issued_at:
            raise ValueError("cannot rotate an expired session")
        revoked = await self._repository.revoke(account_id, previous.id, "rotation")
        if revoked is None:
            raise ValueError("cannot rotate an inactive session")
        return await self.create(
            account_id,
            previous.device_id,
            previous.epoch,
            created_at=issued_at,
            absolute_expires_at=previous.absolute_expires_at,
        )

    async def revoke(
        self,
        account_id: UUID,
        session_id: UUID,
        reason: str = "logout",
    ) -> SessionRecord | None:
        """Revoke one account-owned session."""

        return await self._repository.revoke(account_id, session_id, reason)


async def create_session(
    repository: SessionRepositoryPort,
    account_id: UUID,
    device_id: UUID,
    epoch: int,
    *,
    created_at: datetime | None = None,
) -> CreatedSession:
    """Functional helper for callers that do not need to retain a service object."""

    return await SessionService(repository).create(
        account_id,
        device_id,
        epoch,
        created_at=created_at,
    )


async def rotate_session(
    repository: SessionRepositoryPort,
    account_id: UUID,
    previous: SessionRecord,
    *,
    now: datetime | None = None,
) -> CreatedSession:
    """Functional session-rotation helper."""

    return await SessionService(repository).rotate(account_id, previous, now=now)


async def revoke_session(
    repository: SessionRepositoryPort,
    account_id: UUID,
    session_id: UUID,
    reason: str = "logout",
) -> SessionRecord | None:
    """Functional session-revocation helper."""

    return await SessionService(repository).revoke(account_id, session_id, reason)
