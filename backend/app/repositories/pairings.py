"""Repository operations for account-owned device pairing requests."""

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

    async def record_comparison_attempt(
        self,
        account_id: UUID,
        request_id: UUID,
        maximum_attempts: int = 10,
    ) -> PairingRequestRecord | None:
        """Atomically consume one comparison-code attempt for a pending request."""

        if not 1 <= maximum_attempts <= 10:
            raise ValueError("maximum pairing attempts must be between 1 and 10")
        rows = await self._database.fetch(
            f"""UPDATE private.pairing_requests AS request
            SET attempt_count = request.attempt_count + 1
            WHERE request.user_id = $1
              AND request.id = $2
              AND request.status = 'pending'
              AND request.consumed_at IS NULL
              AND request.expires_at > CURRENT_TIMESTAMP
              AND request.attempt_count < $3
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
            maximum_attempts,
        )
        row = first_row(rows)
        return None if row is None else pairing_request_from_row(row)

    async def reject(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None:
        """Atomically reject one unexpired pending request."""

        rows = await self._database.fetch(
            f"""UPDATE private.pairing_requests AS request
            SET status = 'rejected'
            WHERE request.user_id = $1
              AND request.id = $2
              AND request.status = 'pending'
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


class InMemoryPairingRequestRepository:
    """Explicit test-only pairing-request store used without a database connection."""

    def __init__(self) -> None:
        self._records: dict[UUID, PairingRequestRecord] = {}
        self._lock = threading.Lock()

    async def get_by_id(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None:
        with self._lock:
            record = self._records.get(request_id)
            return record if record is not None and record.user_id == account_id else None

    async def get_pending_by_fingerprint(
        self,
        account_id: UUID,
        requested_fingerprint: bytes,
    ) -> PairingRequestRecord | None:
        current = datetime.now(UTC)
        with self._lock:
            return next(
                (
                    record
                    for record in self._records.values()
                    if record.user_id == account_id
                    and record.requested_fingerprint == bytes(requested_fingerprint)
                    and record.status == "pending"
                    and record.expires_at > current
                ),
                None,
            )

    async def list_pending_for_account(self, account_id: UUID) -> list[PairingRequestRecord]:
        current = datetime.now(UTC)
        with self._lock:
            records = [
                record
                for record in self._records.values()
                if record.user_id == account_id
                and record.status == "pending"
                and record.expires_at > current
            ]
        return sorted(records, key=lambda record: record.created_at, reverse=True)

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
        created_at = datetime.now(UTC)
        if expires_at <= created_at:
            raise ValueError("pairing request expiry must be in the future")
        record = PairingRequestRecord(
            id=uuid4(),
            user_id=account_id,
            requested_public_key_spki=bytes(requested_public_key_spki),
            requested_fingerprint=bytes(requested_fingerprint),
            requested_label=requested_label,
            request_nonce=bytes(request_nonce),
            comparison_code_hash=bytes(comparison_code_hash),
            status="pending",
            attempt_count=0,
            approved_by_device_id=None,
            approval_signature=None,
            created_at=created_at,
            expires_at=expires_at,
            consumed_at=None,
        )
        with self._lock:
            self._records[record.id] = record
        return record

    async def record_comparison_attempt(
        self,
        account_id: UUID,
        request_id: UUID,
        maximum_attempts: int = 10,
    ) -> PairingRequestRecord | None:
        """Atomically consume one comparison-code attempt for a pending request."""

        if not 1 <= maximum_attempts <= 10:
            raise ValueError("maximum pairing attempts must be between 1 and 10")
        current = datetime.now(UTC)
        with self._lock:
            record = self._records.get(request_id)
            if (
                record is None
                or record.user_id != account_id
                or record.status != "pending"
                or record.consumed_at is not None
                or record.expires_at <= current
                or record.attempt_count >= maximum_attempts
            ):
                return None
            updated = replace(record, attempt_count=record.attempt_count + 1)
            self._records[request_id] = updated
            return updated

    async def approve(
        self,
        account_id: UUID,
        request_id: UUID,
        approved_by_device_id: UUID,
        approval_signature: bytes,
    ) -> PairingRequestRecord | None:
        """Atomically approve one unexpired pending request."""

        current = datetime.now(UTC)
        with self._lock:
            record = self._records.get(request_id)
            if (
                record is None
                or record.user_id != account_id
                or record.status != "pending"
                or record.consumed_at is not None
                or record.expires_at <= current
            ):
                return None
            updated = replace(
                record,
                status="approved",
                approved_by_device_id=approved_by_device_id,
                approval_signature=bytes(approval_signature),
            )
            self._records[request_id] = updated
            return updated

    async def reject(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None:
        """Atomically reject one unexpired pending request."""

        current = datetime.now(UTC)
        with self._lock:
            record = self._records.get(request_id)
            if (
                record is None
                or record.user_id != account_id
                or record.status != "pending"
                or record.consumed_at is not None
                or record.expires_at <= current
            ):
                return None
            updated = replace(record, status="rejected")
            self._records[request_id] = updated
            return updated


# Keep schema terminology available to callers that use the table name.
PairingRepository = PairingRequestRepository
