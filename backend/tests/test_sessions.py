from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from app.repositories.models import SessionRecord
from app.sessions import (
    CSRF_SECRET_BYTES,
    SESSION_ABSOLUTE_LIFETIME,
    SESSION_IDLE_LIFETIME,
    SESSION_TOKEN_BYTES,
    SessionService,
    hash_csrf_secret,
    hash_session_token,
    new_opaque_token,
)


def _session_record(
    account_id: UUID,
    device_id: UUID,
    *,
    token_hash: bytes = b"t" * 32,
    csrf_hash: bytes = b"c" * 32,
    created_at: datetime = datetime(2026, 1, 1, tzinfo=UTC),
    idle_expires_at: datetime = datetime(2026, 1, 31, tzinfo=UTC),
    absolute_expires_at: datetime = datetime(2026, 4, 1, tzinfo=UTC),
) -> SessionRecord:
    return SessionRecord(
        id=uuid4(),
        user_id=account_id,
        device_id=device_id,
        token_hash=token_hash,
        csrf_hash=csrf_hash,
        epoch=0,
        created_at=created_at,
        last_seen_at=created_at,
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
        revoked_at=None,
        revocation_reason=None,
    )


class RecordingSessionRepository:
    def __init__(self) -> None:
        self.created: list[tuple[object, ...]] = []
        self.revoked: list[tuple[object, ...]] = []

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
        self.created.append(
            (
                account_id,
                device_id,
                token_hash,
                csrf_hash,
                epoch,
                idle_expires_at,
                absolute_expires_at,
            )
        )
        return _session_record(
            account_id,
            device_id,
            token_hash=token_hash,
            csrf_hash=csrf_hash,
            created_at=idle_expires_at - SESSION_IDLE_LIFETIME,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
        )

    async def revoke(
        self,
        account_id: UUID,
        session_id: UUID,
        reason: str = "logout",
    ) -> SessionRecord | None:
        self.revoked.append((account_id, session_id, reason))
        return _session_record(account_id, uuid4())


def test_opaque_tokens_have_256_bits_and_are_hashable_without_reversal() -> None:
    token = new_opaque_token()
    decoded = base64.urlsafe_b64decode(token + "=")
    assert len(decoded) >= SESSION_TOKEN_BYTES
    assert "=" not in token
    assert len(hash_session_token(token)) == 32
    assert len(hash_csrf_secret(new_opaque_token(CSRF_SECRET_BYTES))) == 32


def test_session_service_creates_device_bound_record_with_documented_expiry() -> None:
    async def exercise() -> None:
        repository = RecordingSessionRepository()
        service = SessionService(repository)
        account_id = uuid4()
        device_id = uuid4()
        created_at = datetime(2026, 1, 1, tzinfo=UTC)

        created = await service.create(account_id, device_id, 0, created_at=created_at)

        assert len(repository.created) == 1
        parameters = repository.created[0]
        assert parameters[:2] == (account_id, device_id)
        assert parameters[2] == created.secrets.token_hash
        assert parameters[3] == created.secrets.csrf_hash
        assert parameters[5] == created_at + SESSION_IDLE_LIFETIME
        assert parameters[6] == created_at + SESSION_ABSOLUTE_LIFETIME
        assert created.record.token_hash == created.secrets.token_hash
        assert created.record.csrf_hash == created.secrets.csrf_hash
        assert created.token != created.csrf_secret

    asyncio.run(exercise())


def test_session_service_requires_a_device_and_rotation_preserves_absolute_expiry() -> None:
    async def exercise() -> None:
        repository = RecordingSessionRepository()
        service = SessionService(repository)
        account_id = uuid4()
        device_id = uuid4()
        previous = _session_record(account_id, device_id)
        now = datetime(2026, 1, 2, tzinfo=UTC)

        with pytest.raises(ValueError, match="device identifier"):
            await service.create(account_id, None, 0)  # type: ignore[arg-type]

        rotated = await service.rotate(account_id, previous, now=now)

        assert repository.revoked == [(account_id, previous.id, "rotation")]
        assert repository.created[-1][6] == previous.absolute_expires_at
        assert rotated.record.absolute_expires_at == previous.absolute_expires_at

    asyncio.run(exercise())


def test_session_service_rejects_expired_rotation() -> None:
    async def exercise() -> None:
        repository = RecordingSessionRepository()
        service = SessionService(repository)
        previous = _session_record(
            uuid4(),
            uuid4(),
            absolute_expires_at=datetime(2026, 1, 2, tzinfo=UTC),
        )

        with pytest.raises(ValueError, match="expired"):
            await service.rotate(
                previous.user_id,
                previous,
                now=datetime(2026, 1, 2, 0, 0, 1, tzinfo=UTC),
            )
        assert not repository.revoked

    asyncio.run(exercise())
