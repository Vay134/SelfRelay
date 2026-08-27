"""Repository operations for one-time device authentication challenges."""

from __future__ import annotations

import secrets
import threading
from dataclasses import replace
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import UUID

from .base import (
    RepositoryDatabase,
    TransactionalRepositoryDatabase,
    first_row,
    required_row,
)
from .models import DeviceChallengeRecord, DeviceRecord, device_challenge_from_row

_DEVICE_CHALLENGE_COLUMNS = """
    id,
    device_id,
    nonce_hash,
    origin,
    created_at,
    expires_at,
    consumed_at,
    attempt_count
"""
_DEVICE_CHALLENGE_SELECT_COLUMNS = """
    challenge.id,
    challenge.device_id,
    challenge.nonce_hash,
    challenge.origin,
    challenge.created_at,
    challenge.expires_at,
    challenge.consumed_at,
    challenge.attempt_count
"""


class _DeviceLookup(Protocol):
    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None: ...


class DeviceChallengeRepository:
    """Persist short-lived challenges for account-owned trusted devices."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def get_by_id(
        self,
        account_id: UUID,
        challenge_id: UUID,
    ) -> DeviceChallengeRecord | None:
        """Return a challenge only when its device belongs to the account."""

        rows = await self._database.fetch(
            f"""SELECT {_DEVICE_CHALLENGE_SELECT_COLUMNS}
            FROM private.device_challenges AS challenge
            JOIN private.devices AS device ON device.id = challenge.device_id
            JOIN private.app_users AS account ON account.id = device.user_id
            WHERE account.id = $1
              AND challenge.id = $2
              AND account.deleted_at IS NULL""",
            account_id,
            challenge_id,
        )
        row = first_row(rows)
        return None if row is None else device_challenge_from_row(row)

    async def get_by_nonce_hash(
        self,
        account_id: UUID,
        nonce_hash: bytes,
    ) -> DeviceChallengeRecord | None:
        """Return a challenge by nonce only when its device belongs to the account."""

        rows = await self._database.fetch(
            f"""SELECT {_DEVICE_CHALLENGE_SELECT_COLUMNS}
            FROM private.device_challenges AS challenge
            JOIN private.devices AS device ON device.id = challenge.device_id
            JOIN private.app_users AS account ON account.id = device.user_id
            WHERE account.id = $1
              AND challenge.nonce_hash = $2
              AND account.deleted_at IS NULL""",
            account_id,
            nonce_hash,
        )
        row = first_row(rows)
        return None if row is None else device_challenge_from_row(row)

    async def create(
        self,
        account_id: UUID,
        device_id: UUID,
        nonce_hash: bytes,
        origin: str,
        expires_at: datetime,
    ) -> DeviceChallengeRecord:
        """Create a challenge only for an active, current-epoch device."""

        rows = await self._database.fetch(
            f"""INSERT INTO private.device_challenges (
                device_id,
                nonce_hash,
                origin,
                expires_at
            )
            SELECT device.id, $3, $4, $5
            FROM private.devices AS device
            JOIN private.app_users AS account ON account.id = device.user_id
            WHERE account.id = $1
              AND device.id = $2
              AND account.deleted_at IS NULL
              AND device.status = 'active'
              AND device.epoch = account.device_epoch
            RETURNING {_DEVICE_CHALLENGE_COLUMNS}""",
            account_id,
            device_id,
            nonce_hash,
            origin,
            expires_at,
        )
        return device_challenge_from_row(required_row(rows))

    async def consume(
        self,
        account_id: UUID,
        challenge_id: UUID,
    ) -> DeviceChallengeRecord | None:
        """Atomically consume one unexpired challenge owned by the account."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            rows = await transaction_database.fetch(
                f"""UPDATE private.device_challenges AS challenge
                SET consumed_at = CURRENT_TIMESTAMP
                WHERE challenge.id = $2
                  AND challenge.consumed_at IS NULL
                  AND challenge.expires_at > CURRENT_TIMESTAMP
                  AND EXISTS (
                      SELECT 1
                      FROM private.devices AS device
                      JOIN private.app_users AS account
                        ON account.id = device.user_id
                      WHERE device.id = challenge.device_id
                        AND account.id = $1
                        AND account.deleted_at IS NULL
                        AND device.status = 'active'
                        AND device.epoch = account.device_epoch
                  )
                RETURNING {_DEVICE_CHALLENGE_COLUMNS}""",
                account_id,
                challenge_id,
            )
        row = first_row(rows)
        return None if row is None else device_challenge_from_row(row)

    async def consume_by_nonce_hash(
        self,
        account_id: UUID,
        nonce_hash: bytes,
    ) -> DeviceChallengeRecord | None:
        """Atomically consume one unexpired challenge identified by its nonce."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            rows = await transaction_database.fetch(
                f"""UPDATE private.device_challenges AS challenge
                SET consumed_at = CURRENT_TIMESTAMP
                WHERE challenge.nonce_hash = $2
                  AND challenge.consumed_at IS NULL
                  AND challenge.expires_at > CURRENT_TIMESTAMP
                  AND EXISTS (
                      SELECT 1
                      FROM private.devices AS device
                      JOIN private.app_users AS account
                        ON account.id = device.user_id
                      WHERE device.id = challenge.device_id
                        AND account.id = $1
                        AND account.deleted_at IS NULL
                        AND device.status = 'active'
                        AND device.epoch = account.device_epoch
                  )
                RETURNING {_DEVICE_CHALLENGE_COLUMNS}""",
                account_id,
                nonce_hash,
            )
        row = first_row(rows)
        return None if row is None else device_challenge_from_row(row)

    async def mark_failed(
        self,
        account_id: UUID,
        challenge_id: UUID,
    ) -> DeviceChallengeRecord | None:
        """Increment failed attempts without consuming a still-valid challenge."""

        rows = await self._database.fetch(
            f"""UPDATE private.device_challenges AS challenge
            SET attempt_count = LEAST(attempt_count + 1, 10)
            WHERE challenge.id = $2
              AND challenge.attempt_count < 10
              AND challenge.consumed_at IS NULL
              AND challenge.expires_at > CURRENT_TIMESTAMP
              AND EXISTS (
                  SELECT 1
                  FROM private.devices AS device
                  JOIN private.app_users AS account ON account.id = device.user_id
                  WHERE device.id = challenge.device_id
                    AND account.id = $1
                    AND account.deleted_at IS NULL
                    AND device.status = 'active'
                    AND device.epoch = account.device_epoch
              )
            RETURNING {_DEVICE_CHALLENGE_COLUMNS}""",
            account_id,
            challenge_id,
        )
        row = first_row(rows)
        return None if row is None else device_challenge_from_row(row)


class InMemoryDeviceChallengeRepository:
    """Explicit test-only one-time challenge repository."""

    def __init__(self, device_repository: _DeviceLookup) -> None:
        self._device_repository = device_repository
        self._records: dict[UUID, DeviceChallengeRecord] = {}
        self._lock = threading.Lock()

    async def create(
        self,
        account_id: UUID,
        device_id: UUID,
        nonce_hash: bytes,
        origin: str,
        expires_at: datetime,
    ) -> DeviceChallengeRecord:
        device = await self._device_repository.get_by_id(account_id, device_id)
        if device is None or device.status != "active":
            raise ValueError("device is not active")
        created_at = datetime.now(UTC)
        record = DeviceChallengeRecord(
            id=UUID(bytes=secrets.token_bytes(16)),
            device_id=device_id,
            nonce_hash=bytes(nonce_hash),
            origin=origin,
            created_at=created_at,
            expires_at=expires_at,
            consumed_at=None,
            attempt_count=0,
        )
        with self._lock:
            if any(existing.nonce_hash == record.nonce_hash for existing in self._records.values()):
                raise ValueError("challenge nonce is already registered")
            self._records[record.id] = record
        return record

    async def get_by_id(
        self,
        account_id: UUID,
        challenge_id: UUID,
    ) -> DeviceChallengeRecord | None:
        with self._lock:
            record = self._records.get(challenge_id)
        if record is None:
            return None
        device = await self._device_repository.get_by_id(account_id, record.device_id)
        return record if device is not None else None

    async def get_by_nonce_hash(
        self,
        account_id: UUID,
        nonce_hash: bytes,
    ) -> DeviceChallengeRecord | None:
        with self._lock:
            record = next(
                (item for item in self._records.values() if item.nonce_hash == bytes(nonce_hash)),
                None,
            )
        if record is None:
            return None
        device = await self._device_repository.get_by_id(account_id, record.device_id)
        return record if device is not None else None

    async def consume(self, account_id: UUID, challenge_id: UUID) -> DeviceChallengeRecord | None:
        record = await self.get_by_id(account_id, challenge_id)
        now = datetime.now(UTC)
        if record is None or record.consumed_at is not None or record.expires_at <= now:
            return None
        device = await self._device_repository.get_by_id(account_id, record.device_id)
        if device is None or device.status != "active":
            return None
        with self._lock:
            current = self._records.get(challenge_id)
            if current is None or current.consumed_at is not None or current.expires_at <= now:
                return None
            consumed = replace(current, consumed_at=now)
            self._records[challenge_id] = consumed
            return consumed

    async def consume_by_nonce_hash(
        self,
        account_id: UUID,
        nonce_hash: bytes,
    ) -> DeviceChallengeRecord | None:
        record = await self.get_by_nonce_hash(account_id, nonce_hash)
        return None if record is None else await self.consume(account_id, record.id)

    async def mark_failed(
        self,
        account_id: UUID,
        challenge_id: UUID,
    ) -> DeviceChallengeRecord | None:
        record = await self.get_by_id(account_id, challenge_id)
        now = datetime.now(UTC)
        if record is None or record.consumed_at is not None or record.expires_at <= now:
            return None
        with self._lock:
            current = self._records.get(challenge_id)
            if current is None or current.consumed_at is not None or current.expires_at <= now:
                return None
            updated = replace(current, attempt_count=min(current.attempt_count + 1, 10))
            self._records[challenge_id] = updated
            return updated


# Keep the shorter name available to callers that use the table's concept.
ChallengeRepository = DeviceChallengeRepository
