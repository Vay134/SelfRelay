"""Repository operations for one-time device-linking codes."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from .base import RepositoryDatabase, TransactionalRepositoryDatabase, first_row, required_row
from .models import (
    DeviceLinkingOtpRecord,
    DeviceRecord,
    device_from_row,
    device_linking_otp_from_row,
)

_OTP_COLUMNS = """
    id,
    user_id,
    issuing_device_id,
    otp_hash,
    status,
    attempt_count,
    created_at,
    expires_at,
    consumed_at
"""

_DEVICE_COLUMNS = """
    id,
    user_id,
    epoch,
    label,
    signing_public_key_spki,
    fingerprint,
    status,
    created_at,
    last_seen_at,
    revoked_at,
    linked_by_device_id
"""


class DeviceLinkingOtpRepository:
    """Persist hashed linking codes and bind their redemption to a new device."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def create(
        self,
        account_id: UUID,
        issuing_device_id: UUID,
        otp_hash: bytes,
        expires_at: datetime,
    ) -> DeviceLinkingOtpRecord:
        rows = await self._database.fetch(
            f"""INSERT INTO private.device_linking_otps (
                user_id,
                issuing_device_id,
                otp_hash,
                expires_at
            )
            SELECT account.id, device.id, $3, $4
            FROM private.app_users AS account
            JOIN private.devices AS device ON device.user_id = account.id
            WHERE account.id = $1
              AND device.id = $2
              AND account.deleted_at IS NULL
              AND device.status = 'active'
              AND device.epoch = account.device_epoch
            RETURNING {_OTP_COLUMNS}""",
            account_id,
            issuing_device_id,
            bytes(otp_hash),
            expires_at,
        )
        return device_linking_otp_from_row(required_row(rows))

    async def get_active_by_hash(self, otp_hash: bytes) -> DeviceLinkingOtpRecord | None:
        rows = await self._database.fetch(
            f"""SELECT {_OTP_COLUMNS}
            FROM private.device_linking_otps AS otp
            JOIN private.app_users AS account ON account.id = otp.user_id
            WHERE otp.otp_hash = $1
              AND otp.status = 'active'
              AND otp.expires_at > CURRENT_TIMESTAMP
              AND account.deleted_at IS NULL""",
            bytes(otp_hash),
        )
        row = first_row(rows)
        return None if row is None else device_linking_otp_from_row(row)

    async def mark_failed(self, otp_id: UUID) -> DeviceLinkingOtpRecord | None:
        rows = await self._database.fetch(
            f"""UPDATE private.device_linking_otps
            SET attempt_count = LEAST(attempt_count + 1, 10),
                status = CASE WHEN attempt_count + 1 >= 10 THEN 'expired' ELSE status END
            WHERE id = $1
              AND status = 'active'
              AND expires_at > CURRENT_TIMESTAMP
              AND attempt_count < 10
            RETURNING {_OTP_COLUMNS}""",
            otp_id,
        )
        row = first_row(rows)
        return None if row is None else device_linking_otp_from_row(row)

    async def consume_and_register(
        self,
        otp_id: UUID,
        account_id: UUID,
        issuing_device_id: UUID,
        epoch: int,
        device_id: UUID,
        label: str,
        signing_public_key_spki: bytes,
        fingerprint: bytes,
    ) -> DeviceRecord | None:
        """Consume the code and insert the device in one database transaction."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            consumed = await transaction_database.fetch(
                """UPDATE private.device_linking_otps AS otp
                SET status = 'consumed', consumed_at = CURRENT_TIMESTAMP
                WHERE otp.id = $1
                  AND otp.user_id = $2
                  AND otp.issuing_device_id = $3
                  AND otp.status = 'active'
                  AND otp.attempt_count < 10
                  AND otp.expires_at > CURRENT_TIMESTAMP
                  AND EXISTS (
                      SELECT 1
                      FROM private.app_users AS account
                      JOIN private.devices AS issuer ON issuer.user_id = account.id
                      WHERE account.id = otp.user_id
                        AND account.deleted_at IS NULL
                        AND account.device_epoch = $4
                        AND issuer.id = otp.issuing_device_id
                        AND issuer.status = 'active'
                        AND issuer.epoch = account.device_epoch
                  )
                RETURNING id""",
                otp_id,
                account_id,
                issuing_device_id,
                epoch,
            )
            if not consumed:
                return None
            rows = await transaction_database.fetch(
                f"""INSERT INTO private.devices (
                    id,
                    user_id,
                    epoch,
                    label,
                    signing_public_key_spki,
                    fingerprint,
                    linked_by_device_id
                )
                SELECT $1, account.id, $3, $4, $5, $6, $7
                FROM private.app_users AS account
                WHERE account.id = $2
                  AND account.deleted_at IS NULL
                  AND account.device_epoch = $3
                RETURNING {_DEVICE_COLUMNS}""",
                device_id,
                account_id,
                epoch,
                label,
                bytes(signing_public_key_spki),
                bytes(fingerprint),
                issuing_device_id,
            )
            return device_from_row(required_row(rows))


class InMemoryDeviceLinkingOtpRepository:
    """Explicit test-only linking-code store with atomic redemption."""

    def __init__(self, device_repository: object) -> None:
        self._device_repository = device_repository
        self._records: dict[UUID, DeviceLinkingOtpRecord] = {}
        self._lock = threading.Lock()
        self._redeem_lock = asyncio.Lock()

    async def create(
        self,
        account_id: UUID,
        issuing_device_id: UUID,
        otp_hash: bytes,
        expires_at: datetime,
    ) -> DeviceLinkingOtpRecord:
        created_at = datetime.now(UTC)
        record = DeviceLinkingOtpRecord(
            id=uuid4(),
            user_id=account_id,
            issuing_device_id=issuing_device_id,
            otp_hash=bytes(otp_hash),
            status="active",
            attempt_count=0,
            created_at=created_at,
            expires_at=expires_at,
            consumed_at=None,
        )
        with self._lock:
            self._records[record.id] = record
        return record

    async def get_active_by_hash(self, otp_hash: bytes) -> DeviceLinkingOtpRecord | None:
        now = datetime.now(UTC)
        with self._lock:
            return next(
                (
                    record
                    for record in self._records.values()
                    if record.otp_hash == bytes(otp_hash)
                    and record.status == "active"
                    and record.expires_at > now
                ),
                None,
            )

    async def mark_failed(self, otp_id: UUID) -> DeviceLinkingOtpRecord | None:
        async with self._redeem_lock:
            now = datetime.now(UTC)
            with self._lock:
                record = self._records.get(otp_id)
                if (
                    record is None
                    or record.status != "active"
                    or record.expires_at <= now
                    or record.attempt_count >= 10
                ):
                    return None
                updated = replace(
                    record,
                    attempt_count=record.attempt_count + 1,
                    status="expired" if record.attempt_count + 1 >= 10 else "active",
                )
                self._records[otp_id] = updated
                return updated

    async def consume_and_register(
        self,
        otp_id: UUID,
        account_id: UUID,
        issuing_device_id: UUID,
        epoch: int,
        device_id: UUID,
        label: str,
        signing_public_key_spki: bytes,
        fingerprint: bytes,
    ) -> DeviceRecord | None:
        async with self._redeem_lock:
            record = await self.get_active_by_hash_for_id(otp_id)
            if (
                record is None
                or record.user_id != account_id
                or record.issuing_device_id != issuing_device_id
                or record.attempt_count >= 10
            ):
                return None
            issuer = await self._device_repository.get_by_id(account_id, issuing_device_id)
            if issuer is None or issuer.status != "active" or issuer.epoch != epoch:
                return None
            device = await self._device_repository.create(
                account_id,
                epoch,
                label,
                signing_public_key_spki,
                fingerprint,
                linked_by_device_id=issuing_device_id,
                device_id=device_id,
            )
            with self._lock:
                current = self._records.get(otp_id)
                if current is None or current.status != "active":
                    return None
                self._records[otp_id] = replace(
                    current,
                    status="consumed",
                    consumed_at=datetime.now(UTC),
                )
            return device

    async def get_active_by_hash_for_id(self, otp_id: UUID) -> DeviceLinkingOtpRecord | None:
        now = datetime.now(UTC)
        with self._lock:
            record = self._records.get(otp_id)
            if record is None or record.status != "active" or record.expires_at <= now:
                return None
            return record


DeviceLinkingOtpStore = DeviceLinkingOtpRepository
