"""Repository operations for account-owned transfer requests."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

from .base import RepositoryDatabase, as_row, first_row, required_row
from .models import TransferRequestRecord, transfer_request_from_row

_TRANSFER_REQUEST_COLUMNS = """
    id,
    user_id,
    sender_device_id,
    recipient_device_id,
    protocol_version,
    status,
    created_at,
    expires_at,
    accepted_at,
    completed_at,
    failure_code,
    relay_used
"""

_ACTIVE_STATUSES = (
    "offered",
    "accepted",
    "negotiating",
    "connected",
    "transferring",
)
_FAILABLE_STATUSES = (
    "accepted",
    "negotiating",
    "connected",
    "transferring",
)
_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "offered": frozenset({"accepted", "rejected", "expired", "cancelled"}),
    "accepted": frozenset({"negotiating", "cancelled", "failed", "expired"}),
    "negotiating": frozenset({"connected", "cancelled", "failed", "expired"}),
    "connected": frozenset({"transferring", "cancelled", "failed", "expired"}),
    "transferring": frozenset({"completed", "cancelled", "failed", "expired"}),
}


def _status_literals(statuses: tuple[str, ...]) -> str:
    """Return a static SQL status list for trusted repository constants."""

    return ", ".join(f"'{status}'" for status in statuses)


class TransferRequestRepository:
    """Persist transfer state while enforcing account and device ownership."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def get_by_id(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Return one transfer only when it belongs to an active account."""

        rows = await self._database.fetch(
            f"""SELECT {_TRANSFER_REQUEST_COLUMNS}
            FROM private.transfer_requests AS transfer
            JOIN private.app_users AS account ON account.id = transfer.user_id
            WHERE transfer.user_id = $1
              AND transfer.id = $2
              AND account.deleted_at IS NULL""",
            account_id,
            transfer_id,
        )
        row = first_row(rows)
        return None if row is None else transfer_request_from_row(row)

    async def list_for_account(self, account_id: UUID) -> list[TransferRequestRecord]:
        """Return an account's transfer records, newest first."""

        rows = await self._database.fetch(
            f"""SELECT {_TRANSFER_REQUEST_COLUMNS}
            FROM private.transfer_requests AS transfer
            JOIN private.app_users AS account ON account.id = transfer.user_id
            WHERE transfer.user_id = $1
              AND account.deleted_at IS NULL
            ORDER BY transfer.created_at DESC""",
            account_id,
        )
        return [transfer_request_from_row(as_row(row)) for row in rows]

    async def list_for_device(
        self,
        account_id: UUID,
        device_id: UUID,
    ) -> list[TransferRequestRecord]:
        """Return transfers involving one account-owned device."""

        rows = await self._database.fetch(
            f"""SELECT {_TRANSFER_REQUEST_COLUMNS}
            FROM private.transfer_requests AS transfer
            JOIN private.app_users AS account ON account.id = transfer.user_id
            WHERE transfer.user_id = $1
              AND (transfer.sender_device_id = $2 OR transfer.recipient_device_id = $2)
              AND account.deleted_at IS NULL
            ORDER BY transfer.created_at DESC""",
            account_id,
            device_id,
        )
        return [transfer_request_from_row(as_row(row)) for row in rows]

    async def create(
        self,
        account_id: UUID,
        sender_device_id: UUID,
        recipient_device_id: UUID,
        protocol_version: int,
        expires_at: datetime,
    ) -> TransferRequestRecord:
        """Create an offer between two active, current-epoch devices."""

        rows = await self._database.fetch(
            f"""INSERT INTO private.transfer_requests (
                user_id,
                sender_device_id,
                recipient_device_id,
                protocol_version,
                expires_at
            )
            SELECT account.id, sender.id, recipient.id, $4, $5
            FROM private.app_users AS account
            JOIN private.devices AS sender
              ON sender.user_id = account.id
            JOIN private.devices AS recipient
              ON recipient.user_id = account.id
            WHERE account.id = $1
              AND account.deleted_at IS NULL
              AND sender.id = $2
              AND sender.status = 'active'
              AND sender.epoch = account.device_epoch
              AND recipient.id = $3
              AND recipient.status = 'active'
              AND recipient.epoch = account.device_epoch
              AND sender.id <> recipient.id
            RETURNING {_TRANSFER_REQUEST_COLUMNS}""",
            account_id,
            sender_device_id,
            recipient_device_id,
            protocol_version,
            expires_at,
        )
        return transfer_request_from_row(required_row(rows))

    async def transition(
        self,
        account_id: UUID,
        transfer_id: UUID,
        from_status: str,
        to_status: str,
    ) -> TransferRequestRecord | None:
        """Apply one documented state transition, returning no row when rejected."""

        allowed_targets = _VALID_TRANSITIONS.get(from_status)
        if allowed_targets is None or to_status not in allowed_targets:
            return None
        return await self._transition(
            account_id,
            transfer_id,
            from_statuses=(from_status,),
            to_status=to_status,
            require_unexpired=to_status != "expired",
        )

    async def accept(
        self,
        account_id: UUID,
        transfer_id: UUID,
        recipient_device_id: UUID,
    ) -> TransferRequestRecord | None:
        """Accept an unexpired offer from its intended active recipient device."""

        return await self._transition(
            account_id,
            transfer_id,
            from_statuses=("offered",),
            to_status="accepted",
            actor_device_id=recipient_device_id,
            actor_role="recipient",
        )

    async def reject(
        self,
        account_id: UUID,
        transfer_id: UUID,
        recipient_device_id: UUID,
    ) -> TransferRequestRecord | None:
        """Reject an unexpired offer from its intended active recipient device."""

        return await self._transition(
            account_id,
            transfer_id,
            from_statuses=("offered",),
            to_status="rejected",
            actor_device_id=recipient_device_id,
            actor_role="recipient",
        )

    async def cancel(
        self,
        account_id: UUID,
        transfer_id: UUID,
        actor_device_id: UUID,
    ) -> TransferRequestRecord | None:
        """Cancel an active transfer from either participating device."""

        return await self._transition(
            account_id,
            transfer_id,
            from_statuses=_ACTIVE_STATUSES,
            to_status="cancelled",
            actor_device_id=actor_device_id,
            actor_role="participant",
        )

    async def mark_negotiating(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Move an accepted transfer into WebRTC negotiation."""

        return await self.transition(account_id, transfer_id, "accepted", "negotiating")

    async def mark_connected(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Record that the peers have connected."""

        return await self.transition(account_id, transfer_id, "negotiating", "connected")

    async def mark_transferring(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Record that encrypted file frames are being sent."""

        return await self.transition(account_id, transfer_id, "connected", "transferring")

    async def complete(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Complete a transfer only after it reached the transferring state."""

        return await self.transition(account_id, transfer_id, "transferring", "completed")

    async def fail(
        self,
        account_id: UUID,
        transfer_id: UUID,
        failure_code: str,
        actor_device_id: UUID | None = None,
    ) -> TransferRequestRecord | None:
        """Move an active transfer to failed with a bounded failure code."""

        return await self._transition(
            account_id,
            transfer_id,
            from_statuses=_FAILABLE_STATUSES,
            to_status="failed",
            actor_device_id=actor_device_id,
            actor_role="participant",
            failure_code=failure_code,
        )

    async def expire(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Mark one stale active transfer expired atomically."""

        return await self._transition(
            account_id,
            transfer_id,
            from_statuses=_ACTIVE_STATUSES,
            to_status="expired",
            require_unexpired=False,
        )

    async def mark_expired(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Compatibility name for callers that use explicit status terminology."""

        return await self.expire(account_id, transfer_id)

    async def mark_complete(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Compatibility name for callers that use a verb-based transition name."""

        return await self.complete(account_id, transfer_id)

    async def mark_failed(
        self,
        account_id: UUID,
        transfer_id: UUID,
        failure_code: str,
        actor_device_id: UUID | None = None,
    ) -> TransferRequestRecord | None:
        """Compatibility name for callers that use a verb-based failure name."""

        return await self.fail(account_id, transfer_id, failure_code, actor_device_id)

    async def mark_relay_used(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Record relay use without changing transfer state."""

        rows = await self._database.fetch(
            f"""UPDATE private.transfer_requests AS transfer
            SET relay_used = TRUE
            WHERE transfer.user_id = $1
              AND transfer.id = $2
              AND transfer.status IN ({_status_literals(_ACTIVE_STATUSES)})
              AND transfer.expires_at > CURRENT_TIMESTAMP
              AND EXISTS (
                  SELECT 1
                  FROM private.app_users AS account
                  WHERE account.id = transfer.user_id
                    AND account.deleted_at IS NULL
              )
            RETURNING {_TRANSFER_REQUEST_COLUMNS}""",
            account_id,
            transfer_id,
        )
        row = first_row(rows)
        return None if row is None else transfer_request_from_row(row)

    async def set_relay_used(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        """Compatibility name for callers that use setter terminology."""

        return await self.mark_relay_used(account_id, transfer_id)

    async def update_status(
        self,
        account_id: UUID,
        transfer_id: UUID,
        from_status: str,
        to_status: str,
    ) -> TransferRequestRecord | None:
        """Compatibility name for callers that use generic status terminology."""

        return await self.transition(account_id, transfer_id, from_status, to_status)

    async def _transition(
        self,
        account_id: UUID,
        transfer_id: UUID,
        *,
        from_statuses: tuple[str, ...],
        to_status: str,
        require_unexpired: bool = True,
        actor_device_id: UUID | None = None,
        actor_role: str | None = None,
        failure_code: str | None = None,
    ) -> TransferRequestRecord | None:
        """Run one atomic, ownership-checked state update."""

        parameters: list[object] = [account_id, transfer_id]
        predicates = [
            f"transfer.status IN ({_status_literals(from_statuses)})",
            (
                "transfer.expires_at > CURRENT_TIMESTAMP"
                if require_unexpired
                else "transfer.expires_at <= CURRENT_TIMESTAMP"
            ),
            "EXISTS (\n"
            "                  SELECT 1\n"
            "                  FROM private.app_users AS account\n"
            "                  WHERE account.id = transfer.user_id\n"
            "                    AND account.deleted_at IS NULL\n"
            "              )",
        ]
        if actor_device_id is not None:
            parameters.append(actor_device_id)
            actor_parameter = len(parameters)
            if actor_role == "recipient":
                role_predicate = "AND actor.id = transfer.recipient_device_id"
            elif actor_role == "participant":
                role_predicate = """AND (
                    actor.id = transfer.sender_device_id
                    OR actor.id = transfer.recipient_device_id
                )"""
            else:
                role_predicate = ""
            predicates.append(
                f"""EXISTS (
                  SELECT 1
                  FROM private.devices AS actor
                  JOIN private.app_users AS account ON account.id = actor.user_id
                  WHERE actor.id = ${actor_parameter}
                    AND actor.user_id = transfer.user_id
                    AND actor.status = 'active'
                    AND actor.epoch = account.device_epoch
                    AND account.deleted_at IS NULL
                    {role_predicate}
              )"""
            )

        set_clauses = [f"status = '{to_status}'", "failure_code = NULL"]
        if to_status == "accepted":
            set_clauses.append("accepted_at = COALESCE(accepted_at, CURRENT_TIMESTAMP)")
        if to_status == "cancelled":
            set_clauses.append("accepted_at = COALESCE(accepted_at, CURRENT_TIMESTAMP)")
        if to_status == "completed":
            set_clauses.append("completed_at = CURRENT_TIMESTAMP")
        if to_status == "failed":
            parameters.append(failure_code)
            failure_parameter = len(parameters)
            set_clauses[-1] = f"failure_code = ${failure_parameter}"

        query = f"""UPDATE private.transfer_requests AS transfer
            SET {", ".join(set_clauses)}
            WHERE transfer.user_id = $1
              AND transfer.id = $2
              AND {" AND ".join(predicates)}
            RETURNING {_TRANSFER_REQUEST_COLUMNS}"""
        rows = await self._database.fetch(query, *parameters)
        row = first_row(rows)
        return None if row is None else transfer_request_from_row(row)

    async def list_by_account(self, account_id: UUID) -> list[TransferRequestRecord]:
        """Compatibility name for callers that use ``by_account`` terminology."""

        return await self.list_for_account(account_id)


class InMemoryTransferRequestRepository:
    """Explicit test-only transfer repository with account-scoped operations."""

    def __init__(
        self,
        device_repository: object | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._records: dict[UUID, TransferRequestRecord] = {}
        self._device_repository = device_repository
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()

    async def get_by_id(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        with self._lock:
            record = self._records.get(transfer_id)
            return record if record is not None and record.user_id == account_id else None

    async def list_for_account(self, account_id: UUID) -> list[TransferRequestRecord]:
        with self._lock:
            records = [record for record in self._records.values() if record.user_id == account_id]
        return sorted(records, key=lambda record: record.created_at, reverse=True)

    async def list_for_device(
        self,
        account_id: UUID,
        device_id: UUID,
    ) -> list[TransferRequestRecord]:
        records = await self.list_for_account(account_id)
        return [
            record
            for record in records
            if record.sender_device_id == device_id or record.recipient_device_id == device_id
        ]

    async def create(
        self,
        account_id: UUID,
        sender_device_id: UUID,
        recipient_device_id: UUID,
        protocol_version: int,
        expires_at: datetime,
    ) -> TransferRequestRecord:
        if sender_device_id == recipient_device_id:
            raise ValueError("sender and recipient must differ")
        if expires_at.tzinfo is None:
            raise ValueError("transfer expiry must be timezone-aware")
        if self._device_repository is not None:
            lookup = getattr(self._device_repository, "get_by_id", None)
            if not callable(lookup):
                raise RuntimeError("device repository cannot validate transfer devices")
            sender = await lookup(account_id, sender_device_id)
            recipient = await lookup(account_id, recipient_device_id)
            if (
                sender is None
                or recipient is None
                or sender.status != "active"
                or recipient.status != "active"
                or sender.epoch != recipient.epoch
            ):
                raise ValueError("transfer devices are unavailable")
        created_at = self._now()
        record = TransferRequestRecord(
            id=uuid4(),
            user_id=account_id,
            sender_device_id=sender_device_id,
            recipient_device_id=recipient_device_id,
            protocol_version=protocol_version,
            status="offered",
            created_at=created_at,
            expires_at=expires_at,
            accepted_at=None,
            completed_at=None,
            failure_code=None,
            relay_used=False,
        )
        with self._lock:
            self._records[record.id] = record
        return record

    async def transition(
        self,
        account_id: UUID,
        transfer_id: UUID,
        from_status: str,
        to_status: str,
    ) -> TransferRequestRecord | None:
        allowed_targets = _VALID_TRANSITIONS.get(from_status)
        if allowed_targets is None or to_status not in allowed_targets:
            return None
        current = self._now()
        with self._lock:
            record = self._records.get(transfer_id)
            if record is None or record.user_id != account_id or record.status != from_status:
                return None
            if to_status == "expired":
                if record.expires_at > current:
                    return None
            elif record.expires_at <= current:
                return None
            updated = self._updated_record(record, to_status)
            self._records[transfer_id] = updated
            return updated

    async def accept(
        self,
        account_id: UUID,
        transfer_id: UUID,
        recipient_device_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self._actor_transition(
            account_id,
            transfer_id,
            from_statuses=("offered",),
            to_status="accepted",
            actor_device_id=recipient_device_id,
            recipient_only=True,
        )

    async def reject(
        self,
        account_id: UUID,
        transfer_id: UUID,
        recipient_device_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self._actor_transition(
            account_id,
            transfer_id,
            from_statuses=("offered",),
            to_status="rejected",
            actor_device_id=recipient_device_id,
            recipient_only=True,
        )

    async def cancel(
        self,
        account_id: UUID,
        transfer_id: UUID,
        actor_device_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self._actor_transition(
            account_id,
            transfer_id,
            from_statuses=_ACTIVE_STATUSES,
            to_status="cancelled",
            actor_device_id=actor_device_id,
            recipient_only=False,
        )

    async def expire(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        expired_offer = await self.transition(account_id, transfer_id, "offered", "expired")
        return expired_offer or await self._expire_active(account_id, transfer_id)

    async def mark_negotiating(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self.transition(account_id, transfer_id, "accepted", "negotiating")

    async def mark_connected(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self.transition(account_id, transfer_id, "negotiating", "connected")

    async def mark_transferring(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self.transition(account_id, transfer_id, "connected", "transferring")

    async def complete(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self.transition(account_id, transfer_id, "transferring", "completed")

    async def fail(
        self,
        account_id: UUID,
        transfer_id: UUID,
        failure_code: str,
        actor_device_id: UUID | None = None,
    ) -> TransferRequestRecord | None:
        if actor_device_id is None:
            for status_value in _FAILABLE_STATUSES:
                result = await self.transition(account_id, transfer_id, status_value, "failed")
                if result is not None:
                    updated = replace(result, failure_code=failure_code)
                    with self._lock:
                        self._records[updated.id] = updated
                    return updated
            return None
        return await self._actor_transition(
            account_id,
            transfer_id,
            from_statuses=_FAILABLE_STATUSES,
            to_status="failed",
            actor_device_id=actor_device_id,
            recipient_only=False,
            failure_code=failure_code,
        )

    async def mark_expired(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self.expire(account_id, transfer_id)

    async def mark_complete(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self.complete(account_id, transfer_id)

    async def mark_failed(
        self,
        account_id: UUID,
        transfer_id: UUID,
        failure_code: str,
        actor_device_id: UUID | None = None,
    ) -> TransferRequestRecord | None:
        return await self.fail(account_id, transfer_id, failure_code, actor_device_id)

    async def mark_relay_used(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        current = self._now()
        with self._lock:
            record = self._records.get(transfer_id)
            if (
                record is None
                or record.user_id != account_id
                or record.status not in _ACTIVE_STATUSES
                or record.expires_at <= current
            ):
                return None
            updated = replace(record, relay_used=True)
            self._records[transfer_id] = updated
            return updated

    async def set_relay_used(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        return await self.mark_relay_used(account_id, transfer_id)

    async def update_status(
        self,
        account_id: UUID,
        transfer_id: UUID,
        from_status: str,
        to_status: str,
    ) -> TransferRequestRecord | None:
        return await self.transition(account_id, transfer_id, from_status, to_status)

    async def list_by_account(self, account_id: UUID) -> list[TransferRequestRecord]:
        return await self.list_for_account(account_id)

    async def _actor_transition(
        self,
        account_id: UUID,
        transfer_id: UUID,
        *,
        from_statuses: tuple[str, ...],
        to_status: str,
        actor_device_id: UUID,
        recipient_only: bool,
        failure_code: str | None = None,
    ) -> TransferRequestRecord | None:
        now = self._now()
        if self._device_repository is not None:
            lookup = getattr(self._device_repository, "get_by_id", None)
            if not callable(lookup):
                return None
            actor = await lookup(account_id, actor_device_id)
            if actor is None or getattr(actor, "status", None) != "active":
                return None
        with self._lock:
            record = self._records.get(transfer_id)
            if (
                record is None
                or record.user_id != account_id
                or record.status not in from_statuses
                or record.expires_at <= now
                or (recipient_only and record.recipient_device_id != actor_device_id)
                or (
                    not recipient_only
                    and actor_device_id not in (record.sender_device_id, record.recipient_device_id)
                )
            ):
                return None
            updated = self._updated_record(record, to_status, failure_code=failure_code)
            self._records[transfer_id] = updated
            return updated

    async def _expire_active(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        now = self._now()
        with self._lock:
            record = self._records.get(transfer_id)
            if (
                record is None
                or record.user_id != account_id
                or record.status not in _ACTIVE_STATUSES
                or record.expires_at > now
            ):
                return None
            updated = self._updated_record(record, "expired")
            self._records[transfer_id] = updated
            return updated

    @staticmethod
    def _updated_record(
        record: TransferRequestRecord,
        status: str,
        *,
        failure_code: str | None = None,
    ) -> TransferRequestRecord:
        return replace(
            record,
            status=status,
            accepted_at=(
                record.accepted_at
                if record.accepted_at is not None
                else datetime.now(record.created_at.tzinfo)
                if status in {"accepted", "cancelled"}
                else None
            ),
            completed_at=(
                datetime.now(record.created_at.tzinfo)
                if status == "completed"
                else record.completed_at
            ),
            failure_code=failure_code,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("transfer timestamps must be timezone-aware")
        return value.astimezone(UTC)


# Keep schema terminology available to callers that use the table name.
TransferRepository = TransferRequestRepository
