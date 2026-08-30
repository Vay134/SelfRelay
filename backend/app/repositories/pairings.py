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
from .models import (
    DeviceRecord,
    PairingRequestRecord,
    SessionRecord,
    device_from_row,
    pairing_request_from_row,
    session_from_row,
)

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
    approval_nonce,
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
    approved_by_device_id
"""

_SESSION_COLUMNS = """
    id,
    user_id,
    device_id,
    token_hash,
    csrf_hash,
    epoch,
    created_at,
    last_seen_at,
    idle_expires_at,
    absolute_expires_at,
    revoked_at,
    revocation_reason
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

    async def get_by_request_id(self, request_id: UUID) -> PairingRequestRecord | None:
        """Return one request by its unguessable public identifier."""

        rows = await self._database.fetch(
            f"""SELECT {_PAIRING_REQUEST_COLUMNS}
            FROM private.pairing_requests AS request
            WHERE request.id = $1
              AND EXISTS (
                  SELECT 1
                  FROM private.app_users AS account
                  WHERE account.id = request.user_id
                    AND account.deleted_at IS NULL
              )""",
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
            f"""WITH expired AS (
                UPDATE private.pairing_requests
                SET status = 'expired'
                WHERE user_id = $1
                  AND requested_fingerprint = $2
                  AND status = 'pending'
                  AND expires_at <= CURRENT_TIMESTAMP
            )
            SELECT {_PAIRING_REQUEST_COLUMNS}
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
        approval_nonce: bytes | None = None,
    ) -> PairingRequestRecord | None:
        """Approve a pending request from an active device in the same account."""

        rows = await self._database.fetch(
            f"""UPDATE private.pairing_requests AS request
            SET status = 'approved',
                approved_by_device_id = $3,
                approval_signature = $4,
                approval_nonce = $5
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
            approval_nonce,
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

    async def finalize_enrollment(
        self,
        account_id: UUID,
        request_id: UUID,
        approved_by_device_id: UUID,
        requested_public_key_spki: bytes,
        requested_fingerprint: bytes,
        requested_label: str,
        epoch: int,
        token_hash: bytes,
        csrf_hash: bytes,
        idle_expires_at: datetime,
        absolute_expires_at: datetime,
    ) -> tuple[PairingRequestRecord, DeviceRecord, SessionRecord] | None:
        """Consume an approval and register its exact device and session atomically."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            request_rows = await transaction_database.fetch(
                f"""UPDATE private.pairing_requests AS request
                SET status = 'consumed',
                    consumed_at = CURRENT_TIMESTAMP
                WHERE request.user_id = $1
                  AND request.id = $2
                  AND request.status = 'approved'
                  AND request.consumed_at IS NULL
                  AND request.expires_at > CURRENT_TIMESTAMP
                  AND request.approved_by_device_id = $3
                  AND request.requested_public_key_spki = $4
                  AND request.requested_fingerprint = $5
                  AND EXISTS (
                      SELECT 1
                      FROM private.app_users AS account
                      JOIN private.devices AS approver
                        ON approver.id = request.approved_by_device_id
                      WHERE account.id = request.user_id
                        AND account.id = $1
                        AND account.deleted_at IS NULL
                        AND account.device_epoch = $6
                        AND approver.user_id = account.id
                        AND approver.status = 'active'
                        AND approver.epoch = account.device_epoch
                  )
                RETURNING {_PAIRING_REQUEST_COLUMNS}""",
                account_id,
                request_id,
                approved_by_device_id,
                requested_public_key_spki,
                requested_fingerprint,
                epoch,
            )
            request_row = first_row(request_rows)
            if request_row is None:
                return None
            request = pairing_request_from_row(request_row)

            device_rows = await transaction_database.fetch(
                f"""INSERT INTO private.devices (
                    user_id,
                    epoch,
                    label,
                    signing_public_key_spki,
                    fingerprint,
                    approved_by_device_id
                )
                SELECT account.id, account.device_epoch, $3, $4, $5, $6
                FROM private.app_users AS account
                JOIN private.devices AS approver
                  ON approver.id = $6
                 AND approver.user_id = account.id
                WHERE account.id = $1
                  AND account.deleted_at IS NULL
                  AND account.device_epoch = $2
                  AND approver.status = 'active'
                  AND approver.epoch = account.device_epoch
                RETURNING {_DEVICE_COLUMNS}""",
                account_id,
                epoch,
                requested_label,
                requested_public_key_spki,
                requested_fingerprint,
                approved_by_device_id,
            )
            device_row = required_row(device_rows)
            device = device_from_row(device_row)

            session_rows = await transaction_database.fetch(
                f"""INSERT INTO private.app_sessions (
                    user_id,
                    device_id,
                    token_hash,
                    csrf_hash,
                    epoch,
                    idle_expires_at,
                    absolute_expires_at
                )
                SELECT account.id, device.id, $3, $4, $5, $6, $7
                FROM private.app_users AS account
                JOIN private.devices AS device
                  ON device.user_id = account.id
                 AND device.id = $2
                WHERE account.id = $1
                  AND account.deleted_at IS NULL
                  AND account.device_epoch = $5
                  AND device.status = 'active'
                  AND device.epoch = account.device_epoch
                RETURNING {_SESSION_COLUMNS}""",
                account_id,
                device.id,
                token_hash,
                csrf_hash,
                epoch,
                idle_expires_at,
                absolute_expires_at,
            )
            session = session_from_row(required_row(session_rows))
        return request, device, session


class InMemoryPairingRequestRepository:
    """Explicit test-only pairing-request store used without a database connection."""

    def __init__(
        self,
        device_store: object | None = None,
        session_repository: object | None = None,
    ) -> None:
        self._records: dict[UUID, PairingRequestRecord] = {}
        self._device_store = device_store
        self._session_repository = session_repository
        self._lock = threading.Lock()

    async def get_by_id(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None:
        with self._lock:
            record = self._records.get(request_id)
            return record if record is not None and record.user_id == account_id else None

    async def get_by_request_id(self, request_id: UUID) -> PairingRequestRecord | None:
        with self._lock:
            return self._records.get(request_id)

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
        approval_nonce: bytes | None = None,
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
                approval_nonce=(None if approval_nonce is None else bytes(approval_nonce)),
            )
            self._records[request_id] = updated
            return updated

    async def finalize_enrollment(
        self,
        account_id: UUID,
        request_id: UUID,
        approved_by_device_id: UUID,
        requested_public_key_spki: bytes,
        requested_fingerprint: bytes,
        requested_label: str,
        epoch: int,
        token_hash: bytes,
        csrf_hash: bytes,
        idle_expires_at: datetime,
        absolute_expires_at: datetime,
    ) -> tuple[PairingRequestRecord, DeviceRecord, SessionRecord] | None:
        """Finalize one request with the test stores and roll back on failure."""

        if self._device_store is None or self._session_repository is None:
            raise RuntimeError("pairing enrollment stores are not configured")
        current = datetime.now(UTC)
        with self._lock:
            record = self._records.get(request_id)
            if (
                record is None
                or record.user_id != account_id
                or record.status != "approved"
                or record.consumed_at is not None
                or record.expires_at <= current
                or record.approved_by_device_id != approved_by_device_id
                or record.requested_public_key_spki != bytes(requested_public_key_spki)
                or record.requested_fingerprint != bytes(requested_fingerprint)
            ):
                return None
            consumed = replace(record, status="consumed", consumed_at=current)
            self._records[request_id] = consumed

        device: DeviceRecord | None = None
        session: SessionRecord | None = None
        try:
            create_device = self._device_store.create  # type: ignore[attr-defined]
            device = await create_device(
                account_id,
                epoch,
                requested_label,
                bytes(requested_public_key_spki),
                bytes(requested_fingerprint),
                approved_by_device_id,
            )
            create_session = self._session_repository.create  # type: ignore[attr-defined]
            session = await create_session(
                account_id,
                device.id,
                bytes(token_hash),
                bytes(csrf_hash),
                epoch,
                idle_expires_at,
                absolute_expires_at,
            )
        except Exception:
            with self._lock:
                self._records[request_id] = record
            if session is not None:
                remove_session = getattr(self._session_repository, "remove", None)
                if callable(remove_session):
                    await remove_session(account_id, session.id)
            if device is not None:
                remove_device = getattr(self._device_store, "remove", None)
                if callable(remove_device):
                    await remove_device(account_id, device.id)
            raise
        return consumed, device, session

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
