"""Opaque application-session primitives for the device-authenticated API."""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
from collections.abc import Awaitable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
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

    async def reissue_csrf(
        self,
        account_id: UUID,
        session_id: UUID,
    ) -> tuple[str, SessionRecord]:
        """Rotate the CSRF secret for an already-authenticated session."""

        replacer = getattr(self._repository, "replace_csrf_hash", None)
        if not callable(replacer):
            raise RuntimeError("session repository cannot rotate CSRF values")
        csrf_secret = generate_csrf_secret()
        replacement = replacer(account_id, session_id, hash_csrf_secret(csrf_secret))
        updated = await cast(Awaitable[SessionRecord | None], replacement)
        if updated is None:
            raise ValueError("cannot rotate CSRF for an inactive session")
        return csrf_secret, updated


class InMemorySessionRepository:
    """Explicit test-only session store used without a database connection."""

    def __init__(self) -> None:
        self._records: dict[UUID, SessionRecord] = {}
        self._by_token_hash: dict[bytes, UUID] = {}
        self._lock = threading.Lock()

    async def create(
        self,
        account_id: UUID,
        device_id: UUID,
        token_hash: bytes,
        csrf_hash: bytes,
        epoch: int,
        idle_expires_at: datetime,
        absolute_expires_at: datetime,
    ) -> SessionRecord:
        created_at = datetime.now(UTC)
        record = SessionRecord(
            id=UUID(bytes=secrets.token_bytes(16)),
            user_id=account_id,
            device_id=device_id,
            token_hash=bytes(token_hash),
            csrf_hash=bytes(csrf_hash),
            epoch=epoch,
            created_at=created_at,
            last_seen_at=created_at,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
            revoked_at=None,
            revocation_reason=None,
        )
        with self._lock:
            self._records[record.id] = record
            self._by_token_hash[record.token_hash] = record.id
        return record

    async def find_by_token_hash(self, token_hash: bytes) -> SessionRecord | None:
        current = datetime.now(UTC)
        with self._lock:
            record_id = self._by_token_hash.get(bytes(token_hash))
            record = None if record_id is None else self._records.get(record_id)
            if record is None or not self._is_usable(record, current):
                return None
            return record

    async def get_by_token_hash(
        self,
        account_id: UUID,
        token_hash: bytes,
    ) -> SessionRecord | None:
        record = await self.find_by_token_hash(token_hash)
        return record if record is not None and record.user_id == account_id else None

    async def list_for_account(self, account_id: UUID) -> list[SessionRecord]:
        with self._lock:
            records = [record for record in self._records.values() if record.user_id == account_id]
        return sorted(records, key=lambda record: record.created_at, reverse=True)

    async def touch_last_seen(
        self,
        account_id: UUID,
        session_id: UUID,
    ) -> SessionRecord | None:
        current = datetime.now(UTC)
        with self._lock:
            record = self._records.get(session_id)
            if (
                record is None
                or record.user_id != account_id
                or not self._is_usable(record, current)
            ):
                return None
            updated = self._replace(
                record,
                last_seen_at=current,
                idle_expires_at=min(current + SESSION_IDLE_LIFETIME, record.absolute_expires_at),
            )
            self._records[session_id] = updated
            return updated

    async def replace_csrf_hash(
        self,
        account_id: UUID,
        session_id: UUID,
        csrf_hash: bytes,
    ) -> SessionRecord | None:
        current = datetime.now(UTC)
        with self._lock:
            record = self._records.get(session_id)
            if (
                record is None
                or record.user_id != account_id
                or not self._is_usable(record, current)
            ):
                return None
            updated = self._replace(record, csrf_hash=bytes(csrf_hash))
            self._records[session_id] = updated
            return updated

    async def revoke(
        self,
        account_id: UUID,
        session_id: UUID,
        reason: str = "logout",
    ) -> SessionRecord | None:
        current = datetime.now(UTC)
        with self._lock:
            record = self._records.get(session_id)
            if record is None or record.user_id != account_id or record.revoked_at is not None:
                return None
            updated = self._replace(
                record,
                revoked_at=current,
                revocation_reason=reason,
            )
            self._records[session_id] = updated
            return updated

    async def revoke_by_token_hash(
        self,
        account_id: UUID,
        token_hash: bytes,
        reason: str = "logout",
    ) -> SessionRecord | None:
        record = await self.get_by_token_hash(account_id, token_hash)
        if record is None:
            return None
        return await self.revoke(account_id, record.id, reason)

    async def revoke_for_device(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "device_revoked",
    ) -> int:
        current = datetime.now(UTC)
        with self._lock:
            targets = [
                record
                for record in self._records.values()
                if record.user_id == account_id
                and record.device_id == device_id
                and record.revoked_at is None
            ]
            for record in targets:
                self._records[record.id] = self._replace(
                    record,
                    revoked_at=current,
                    revocation_reason=reason,
                )
            return len(targets)

    async def revoke_for_account(
        self,
        account_id: UUID,
        reason: str = "recovery",
    ) -> int:
        current = datetime.now(UTC)
        with self._lock:
            targets = [
                record
                for record in self._records.values()
                if record.user_id == account_id and record.revoked_at is None
            ]
            for record in targets:
                self._records[record.id] = self._replace(
                    record,
                    revoked_at=current,
                    revocation_reason=reason,
                )
            return len(targets)

    @staticmethod
    def _is_usable(record: SessionRecord, current: datetime) -> bool:
        current = current.astimezone(UTC)
        return (
            record.revoked_at is None
            and record.idle_expires_at > current
            and record.absolute_expires_at > current
        )

    @staticmethod
    def _replace(record: SessionRecord, **changes: object) -> SessionRecord:
        return replace(record, **changes)  # type: ignore[arg-type]


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
