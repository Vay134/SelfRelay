"""Repository operations for account-owned trusted devices."""

from __future__ import annotations

from typing import cast
from uuid import UUID

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
    approved_by_device_id
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
        approved_by_device_id: UUID | None = None,
    ) -> DeviceRecord:
        """Create a current-epoch device after checking account ownership."""

        rows = await self._database.fetch(
            f"""INSERT INTO private.devices (
                user_id,
                epoch,
                label,
                signing_public_key_spki,
                fingerprint,
                approved_by_device_id
            )
            SELECT account.id, $2, $3, $4, $5, $6
            FROM private.app_users AS account
            WHERE account.id = $1
              AND account.deleted_at IS NULL
              AND account.device_epoch = $2
              AND (
                  $6::uuid IS NULL
                  OR EXISTS (
                      SELECT 1
                      FROM private.devices AS approver
                      WHERE approver.id = $6
                        AND approver.user_id = account.id
                        AND approver.status = 'active'
                        AND approver.epoch = account.device_epoch
                  )
              )
            RETURNING {_DEVICE_COLUMNS}""",
            account_id,
            epoch,
            label,
            signing_public_key_spki,
            fingerprint,
            approved_by_device_id,
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

    async def revoke(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "device_revoked",
    ) -> DeviceRecord | None:
        """Revoke an account-owned device and all of its active sessions."""

        return await self.revoke_with_sessions(account_id, device_id, reason)

    async def list_by_account(self, account_id: UUID) -> list[DeviceRecord]:
        """Compatibility name for callers that use ``by_account`` terminology."""

        return await self.list_for_account(account_id)


# Keep schema terminology available to callers that use the table name.
TrustedDeviceRepository = DeviceRepository
