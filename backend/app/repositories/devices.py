"""Repository operations for account-owned trusted devices."""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from .base import (
    RepositoryDatabase,
    TransactionalRepositoryDatabase,
    as_row,
    first_row,
    required_row,
)
from .models import DeviceRecord, device_from_row

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


class DeviceRepository:
    """Persist trusted devices while keeping every operation account-scoped."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None:
        """Return one device only when it belongs to the requested account."""

        rows = await self._database.fetch(
            f"""SELECT {_DEVICE_COLUMNS}
            FROM private.devices
            WHERE user_id = $1 AND id = $2""",
            account_id,
            device_id,
        )
        row = first_row(rows)
        return None if row is None else device_from_row(row)

    async def get_by_fingerprint(
        self,
        account_id: UUID,
        fingerprint: bytes,
    ) -> DeviceRecord | None:
        """Return one account-owned device by its public-key fingerprint."""

        rows = await self._database.fetch(
            f"""SELECT {_DEVICE_COLUMNS}
            FROM private.devices
            WHERE user_id = $1 AND fingerprint = $2""",
            account_id,
            fingerprint,
        )
        row = first_row(rows)
        return None if row is None else device_from_row(row)

    async def list_for_account(self, account_id: UUID) -> list[DeviceRecord]:
        """Return all devices belonging to one account, newest first."""

        rows = await self._database.fetch(
            f"""SELECT {_DEVICE_COLUMNS}
            FROM private.devices
            WHERE user_id = $1
            ORDER BY created_at DESC""",
            account_id,
        )
        return [device_from_row(as_row(row)) for row in rows]

    async def create(
        self,
        account_id: UUID,
        epoch: int,
        label: str,
        signing_public_key_spki: bytes,
        fingerprint: bytes,
        *,
        linked_by_device_id: UUID | None = None,
        device_id: UUID | None = None,
    ) -> DeviceRecord:
        """Create a current-epoch device after checking account ownership."""

        rows = await self._database.fetch(
            f"""INSERT INTO private.devices (
                id,
                user_id,
                epoch,
                label,
                signing_public_key_spki,
                fingerprint,
                linked_by_device_id
            )
            SELECT COALESCE($2::uuid, gen_random_uuid()), account.id, $3, $4, $5, $6, $7
            FROM private.app_users AS account
            WHERE account.id = $1
              AND account.deleted_at IS NULL
              AND account.device_epoch = $3
              AND (
                  $7::uuid IS NULL
                  OR EXISTS (
                      SELECT 1
                      FROM private.devices AS approver
                      WHERE approver.id = $7
                        AND approver.user_id = account.id
                        AND approver.status = 'active'
                        AND approver.epoch = account.device_epoch
                  )
              )
            RETURNING {_DEVICE_COLUMNS}""",
            account_id,
            device_id,
            epoch,
            label,
            signing_public_key_spki,
            fingerprint,
            linked_by_device_id,
        )
        return device_from_row(required_row(rows))

    async def register_for_email(
        self,
        account_id: UUID,
        epoch: int,
        label: str,
        signing_public_key_spki: bytes,
        fingerprint: bytes,
        device_id: UUID,
    ) -> DeviceRecord:
        """Activate this key or register it without changing other devices."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            existing_rows = await transaction_database.fetch(
                f"""SELECT {_DEVICE_COLUMNS}
                FROM private.devices
                WHERE user_id = $1 AND fingerprint = $2
                FOR UPDATE""",
                account_id,
                bytes(fingerprint),
            )
            existing = first_row(existing_rows)
            if existing is not None:
                existing_device = device_from_row(existing)
                if existing_device.status == "revoked":
                    raise ValueError("revoked devices cannot be reactivated")
                rows = await transaction_database.fetch(
                    f"""UPDATE private.devices
                    SET status = 'active',
                        label = $3,
                        last_seen_at = CURRENT_TIMESTAMP
                    WHERE user_id = $1 AND fingerprint = $2 AND epoch = $4
                    RETURNING {_DEVICE_COLUMNS}""",
                    account_id,
                    bytes(fingerprint),
                    label,
                    epoch,
                )
                return device_from_row(required_row(rows))
            rows = await transaction_database.fetch(
                f"""INSERT INTO private.devices (
                    id,
                    user_id,
                    epoch,
                    label,
                    signing_public_key_spki,
                    fingerprint
                )
                SELECT $1, account.id, $2, $3, $4, $5
                FROM private.app_users AS account
                WHERE account.id = $6
                  AND account.deleted_at IS NULL
                  AND account.device_epoch = $2
                RETURNING {_DEVICE_COLUMNS}""",
                device_id,
                epoch,
                label,
                bytes(signing_public_key_spki),
                bytes(fingerprint),
                account_id,
            )
            return device_from_row(required_row(rows))

    async def touch_last_seen(
        self,
        account_id: UUID,
        device_id: UUID,
    ) -> DeviceRecord | None:
        """Update activity only for an account-owned active device."""

        rows = await self._database.fetch(
            f"""UPDATE private.devices
            SET last_seen_at = CURRENT_TIMESTAMP
            WHERE user_id = $1 AND id = $2 AND status = 'active'
            RETURNING {_DEVICE_COLUMNS}""",
            account_id,
            device_id,
        )
        row = first_row(rows)
        return None if row is None else device_from_row(row)

    async def rename(
        self,
        account_id: UUID,
        device_id: UUID,
        label: str,
    ) -> DeviceRecord | None:
        """Rename one account-owned device without changing its identity."""

        rows = await self._database.fetch(
            f"""UPDATE private.devices
            SET label = $3
            WHERE user_id = $1 AND id = $2
            RETURNING {_DEVICE_COLUMNS}""",
            account_id,
            device_id,
            label,
        )
        row = first_row(rows)
        return None if row is None else device_from_row(row)

    async def revoke_with_sessions(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "device_revoked",
    ) -> DeviceRecord | None:
        """Revoke a device and its sessions atomically on one connection."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        device: DeviceRecord | None = None
        async with database.transaction() as transaction_database:
            rows = await transaction_database.fetch(
                f"""UPDATE private.devices
                SET status = 'revoked',
                    revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
                WHERE user_id = $1 AND id = $2
                RETURNING {_DEVICE_COLUMNS}""",
                account_id,
                device_id,
            )
            row = first_row(rows)
            if row is not None:
                device = device_from_row(row)
                await transaction_database.fetch(
                    """UPDATE private.app_sessions
                    SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP),
                        revocation_reason = $3
                    WHERE user_id = $1
                      AND device_id = $2
                      AND revoked_at IS NULL
                    RETURNING id""",
                    account_id,
                    device_id,
                    reason,
                )
        return device

    async def logout_with_sessions(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "logout",
    ) -> DeviceRecord | None:
        """Mark a device inactive and revoke every session on that device."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        device: DeviceRecord | None = None
        async with database.transaction() as transaction_database:
            rows = await transaction_database.fetch(
                f"""UPDATE private.devices
                SET status = CASE WHEN status = 'revoked' THEN status ELSE 'inactive' END
                WHERE user_id = $1 AND id = $2
                RETURNING {_DEVICE_COLUMNS}""",
                account_id,
                device_id,
            )
            row = first_row(rows)
            if row is not None:
                device = device_from_row(row)
                await transaction_database.fetch(
                    """UPDATE private.app_sessions
                    SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP),
                        revocation_reason = $3
                    WHERE user_id = $1
                      AND device_id = $2
                      AND revoked_at IS NULL
                    RETURNING id""",
                    account_id,
                    device_id,
                    reason,
                )
        return device

    async def revoke(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "device_revoked",
    ) -> DeviceRecord | None:
        """Revoke an account-owned device and all of its active sessions."""

        return await self.revoke_with_sessions(account_id, device_id, reason)

    async def revoke_all_for_account(
        self,
        account_id: UUID,
        reason: str = "account_cleanup",
    ) -> int:
        """Revoke every account device and its sessions in one transaction."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            rows = await transaction_database.fetch(
                """UPDATE private.devices AS device
                SET status = 'revoked',
                    revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
                WHERE device.user_id = $1
                  AND device.status = 'active'
                RETURNING device.id""",
                account_id,
            )
            await transaction_database.fetch(
                """UPDATE private.app_sessions
                SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP),
                    revocation_reason = $2
                WHERE user_id = $1
                  AND revoked_at IS NULL
                RETURNING id""",
                account_id,
                reason,
            )
        return len(rows)

    async def list_by_account(self, account_id: UUID) -> list[DeviceRecord]:
        """Compatibility name for callers that use ``by_account`` terminology."""

        return await self.list_for_account(account_id)


class InMemoryDeviceRepository:
    """Explicit test-only device repository with account-scoped operations."""

    def __init__(
        self,
        session_repository: object | None = None,
    ) -> None:
        self._records: dict[UUID, DeviceRecord] = {}
        self._session_repository = session_repository
        self._lock = threading.Lock()

    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None:
        with self._lock:
            record = self._records.get(device_id)
            return record if record is not None and record.user_id == account_id else None

    async def get_by_fingerprint(
        self,
        account_id: UUID,
        fingerprint: bytes,
    ) -> DeviceRecord | None:
        with self._lock:
            return next(
                (
                    record
                    for record in self._records.values()
                    if record.user_id == account_id and record.fingerprint == bytes(fingerprint)
                ),
                None,
            )

    async def list_for_account(self, account_id: UUID) -> list[DeviceRecord]:
        with self._lock:
            records = [record for record in self._records.values() if record.user_id == account_id]
        return sorted(records, key=lambda record: record.created_at, reverse=True)

    async def create(
        self,
        account_id: UUID,
        epoch: int,
        label: str,
        signing_public_key_spki: bytes,
        fingerprint: bytes,
        *,
        linked_by_device_id: UUID | None = None,
        device_id: UUID | None = None,
    ) -> DeviceRecord:
        created_at = datetime.now(UTC)
        record = DeviceRecord(
            id=device_id or uuid4(),
            user_id=account_id,
            epoch=epoch,
            label=label,
            signing_public_key_spki=bytes(signing_public_key_spki),
            fingerprint=bytes(fingerprint),
            status="active",
            created_at=created_at,
            last_seen_at=created_at,
            revoked_at=None,
            linked_by_device_id=linked_by_device_id,
        )
        with self._lock:
            if any(
                existing.user_id == account_id and existing.fingerprint == record.fingerprint
                for existing in self._records.values()
            ):
                raise ValueError("device fingerprint is already registered")
            self._records[record.id] = record
        return record

    async def register_for_email(
        self,
        account_id: UUID,
        epoch: int,
        label: str,
        signing_public_key_spki: bytes,
        fingerprint: bytes,
        device_id: UUID,
    ) -> DeviceRecord:
        with self._lock:
            existing = next(
                (
                    record
                    for record in self._records.values()
                    if record.user_id == account_id and record.fingerprint == bytes(fingerprint)
                ),
                None,
            )
            if existing is not None:
                if existing.status == "revoked":
                    raise ValueError("revoked devices cannot be reactivated")
                updated = replace(
                    existing,
                    epoch=epoch,
                    label=label,
                    status="active",
                    last_seen_at=datetime.now(UTC),
                )
                self._records[existing.id] = updated
                return updated
            return_record = DeviceRecord(
                id=device_id,
                user_id=account_id,
                epoch=epoch,
                label=label,
                signing_public_key_spki=bytes(signing_public_key_spki),
                fingerprint=bytes(fingerprint),
                status="active",
                created_at=datetime.now(UTC),
                last_seen_at=datetime.now(UTC),
                revoked_at=None,
                linked_by_device_id=None,
            )
            if any(record.id == device_id for record in self._records.values()):
                raise ValueError("device identifier is already registered")
            self._records[device_id] = return_record
            return return_record

    async def remove(self, account_id: UUID, device_id: UUID) -> bool:
        """Remove a just-created test device during a failed compound operation."""

        with self._lock:
            record = self._records.get(device_id)
            if record is None or record.user_id != account_id:
                return False
            del self._records[device_id]
            return True

    async def touch_last_seen(
        self,
        account_id: UUID,
        device_id: UUID,
    ) -> DeviceRecord | None:
        with self._lock:
            record = self._records.get(device_id)
            if record is None or record.user_id != account_id or record.status != "active":
                return None
            updated = replace(record, last_seen_at=datetime.now(UTC))
            self._records[device_id] = updated
            return updated

    async def rename(
        self,
        account_id: UUID,
        device_id: UUID,
        label: str,
    ) -> DeviceRecord | None:
        with self._lock:
            record = self._records.get(device_id)
            if record is None or record.user_id != account_id:
                return None
            updated = replace(record, label=label)
            self._records[device_id] = updated
            return updated

    async def revoke_with_sessions(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "device_revoked",
    ) -> DeviceRecord | None:
        with self._lock:
            record = self._records.get(device_id)
            if record is None or record.user_id != account_id:
                return None
            if record.status == "revoked":
                return record
            updated = replace(
                record,
                status="revoked",
                revoked_at=datetime.now(UTC),
            )
            self._records[device_id] = updated
        revoker = getattr(self._session_repository, "revoke_for_device", None)
        if callable(revoker):
            await revoker(account_id, device_id, reason)
        return updated

    async def logout_with_sessions(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "logout",
    ) -> DeviceRecord | None:
        with self._lock:
            record = self._records.get(device_id)
            if record is None or record.user_id != account_id:
                return None
            if record.status != "revoked":
                record = replace(record, status="inactive")
                self._records[device_id] = record
        revoker = getattr(self._session_repository, "revoke_for_device", None)
        if callable(revoker):
            await revoker(account_id, device_id, reason)
        return record

    async def revoke(
        self, account_id: UUID, device_id: UUID, reason: str = "device_revoked"
    ) -> DeviceRecord | None:
        return await self.revoke_with_sessions(account_id, device_id, reason)

    async def revoke_all_for_account(
        self,
        account_id: UUID,
        reason: str = "account_cleanup",
    ) -> int:
        with self._lock:
            targets = [
                record
                for record in self._records.values()
                if record.user_id == account_id and record.status == "active"
            ]
            now = datetime.now(UTC)
            for record in targets:
                self._records[record.id] = replace(
                    record,
                    status="revoked",
                    revoked_at=now,
                )
        revoker = getattr(self._session_repository, "revoke_for_device", None)
        if callable(revoker):
            for record in targets:
                await revoker(account_id, record.id, reason)
        return len(targets)


# Keep schema terminology available to callers that use the table name.
TrustedDeviceRepository = DeviceRepository
