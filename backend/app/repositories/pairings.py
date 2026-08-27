"""Repository operations for account-owned device pairing requests."""

from __future__ import annotations

from datetime import datetime
from typing import cast
from uuid import UUID

from .base import (
    RepositoryDatabase,
    TransactionalRepositoryDatabase,
    as_row,
    first_row,
    required_row,
)
from .models import PairingRequestRecord, pairing_request_from_row

_PAIRING_REQUEST_COLUMNS = """
    id,
    user_id,
    requested_public_key_spki,
    requested_fingerprint,
    requested_label,
    request_nonce,
    comparison_code_hash,
    status,
    attempt_count,
    approved_by_device_id,
    approval_signature,
    created_at,
    expires_at,
    consumed_at
"""


class PairingRequestRepository:
    """Persist pairing requests while keeping every operation account-scoped."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def get_by_id(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None:
        """Return one pairing request only when it belongs to the account."""

        rows = await self._database.fetch(
            f"""SELECT {_PAIRING_REQUEST_COLUMNS}
            FROM private.pairing_requests
            WHERE user_id = $1
              AND id = $2
              AND EXISTS (
                  SELECT 1
                  FROM private.app_users AS account
                  WHERE account.id = private.pairing_requests.user_id
                    AND account.deleted_at IS NULL
              )""",
            account_id,
            request_id,
        )
        row = first_row(rows)
        return None if row is None else pairing_request_from_row(row)

    async def get_pending_by_fingerprint(
        self,
        account_id: UUID,
        requested_fingerprint: bytes,
    ) -> PairingRequestRecord | None:
        """Return a pending request by fingerprint for one active account."""

        rows = await self._database.fetch(
            f"""SELECT {_PAIRING_REQUEST_COLUMNS}
            FROM private.pairing_requests
            WHERE user_id = $1
              AND requested_fingerprint = $2
              AND status = 'pending'
              AND expires_at > CURRENT_TIMESTAMP
              AND EXISTS (
                  SELECT 1
                  FROM private.app_users AS account
                  WHERE account.id = private.pairing_requests.user_id
                    AND account.deleted_at IS NULL
              )""",
            account_id,
            requested_fingerprint,
        )
        row = first_row(rows)
        return None if row is None else pairing_request_from_row(row)

    async def list_pending_for_account(self, account_id: UUID) -> list[PairingRequestRecord]:
        """Return unexpired pending requests for one active account."""

        rows = await self._database.fetch(
            f"""SELECT {_PAIRING_REQUEST_COLUMNS}
            FROM private.pairing_requests
            WHERE user_id = $1
              AND status = 'pending'
              AND expires_at > CURRENT_TIMESTAMP
              AND EXISTS (
                  SELECT 1
                  FROM private.app_users AS account
                  WHERE account.id = private.pairing_requests.user_id
                    AND account.deleted_at IS NULL
              )
            ORDER BY created_at DESC""",
            account_id,
        )
        return [pairing_request_from_row(as_row(row)) for row in rows]

    async def create(
        self,
        account_id: UUID,
        requested_public_key_spki: bytes,
        requested_fingerprint: bytes,
        requested_label: str,
        request_nonce: bytes,
        comparison_code_hash: bytes,
        expires_at: datetime,
    ) -> PairingRequestRecord:
        """Create a pairing request for an active account."""

        rows = await self._database.fetch(
            f"""INSERT INTO private.pairing_requests (
                user_id,
                requested_public_key_spki,
                requested_fingerprint,
                requested_label,
                request_nonce,
                comparison_code_hash,
                expires_at
            )
            SELECT account.id, $2, $3, $4, $5, $6, $7
            FROM private.app_users AS account
            WHERE account.id = $1
              AND account.deleted_at IS NULL
            RETURNING {_PAIRING_REQUEST_COLUMNS}""",
            account_id,
            requested_public_key_spki,
            requested_fingerprint,
            requested_label,
            request_nonce,
            comparison_code_hash,
            expires_at,
        )
        return pairing_request_from_row(required_row(rows))

    async def approve(
        self,
        account_id: UUID,
        request_id: UUID,
        approved_by_device_id: UUID,
        approval_signature: bytes,
    ) -> PairingRequestRecord | None:
        """Approve a pending request from an active device in the same account."""

        rows = await self._database.fetch(
            f"""UPDATE private.pairing_requests AS request
            SET status = 'approved',
                approved_by_device_id = $3,
                approval_signature = $4
            WHERE request.id = $2
              AND request.user_id = $1
              AND request.status = 'pending'
              AND request.consumed_at IS NULL
              AND request.expires_at > CURRENT_TIMESTAMP
              AND EXISTS (
                  SELECT 1
                  FROM private.app_users AS account
                  JOIN private.devices AS device ON device.user_id = account.id
                  WHERE account.id = request.user_id
                    AND account.id = $1
                    AND account.deleted_at IS NULL
                    AND device.id = $3
                    AND device.status = 'active'
                    AND device.epoch = account.device_epoch
              )
            RETURNING {_PAIRING_REQUEST_COLUMNS}""",
            account_id,
            request_id,
            approved_by_device_id,
            approval_signature,
        )
        row = first_row(rows)
        return None if row is None else pairing_request_from_row(row)

    async def consume(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None:
        """Atomically consume one unexpired approved request owned by the account."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            rows = await transaction_database.fetch(
                f"""UPDATE private.pairing_requests AS request
                SET status = 'consumed',
                    consumed_at = CURRENT_TIMESTAMP
                WHERE request.user_id = $1
                  AND request.id = $2
                  AND request.status = 'approved'
                  AND request.consumed_at IS NULL
                  AND request.expires_at > CURRENT_TIMESTAMP
                  AND EXISTS (
                      SELECT 1
                      FROM private.app_users AS account
                      WHERE account.id = request.user_id
                        AND account.id = $1
                        AND account.deleted_at IS NULL
                  )
                RETURNING {_PAIRING_REQUEST_COLUMNS}""",
                account_id,
                request_id,
            )
        row = first_row(rows)
        return None if row is None else pairing_request_from_row(row)

    async def consume_approved(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None:
        """Compatibility name for callers that make the approval precondition explicit."""

        return await self.consume(account_id, request_id)


# Keep schema terminology available to callers that use the table name.
PairingRepository = PairingRequestRepository
