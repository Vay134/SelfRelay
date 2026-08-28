"""Repository operations for short-lived security audit events."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from uuid import UUID, uuid4

from .base import RepositoryDatabase, as_row, first_row, required_row
from .models import SecurityEventRecord, security_event_from_row

_SECURITY_EVENT_COLUMNS = """
    id,
    user_id,
    device_id,
    event_type,
    outcome,
    network_fingerprint,
    details,
    created_at,
    expires_at
"""


class SecurityEventRepository:
    """Persist allowlisted, bounded security events without raw secrets."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def get_by_id(
        self,
        account_id: UUID,
        event_id: UUID,
    ) -> SecurityEventRecord | None:
        """Return one event only when it belongs to the requested account."""

        rows = await self._database.fetch(
            f"""SELECT {_SECURITY_EVENT_COLUMNS}
            FROM private.security_events AS event
            JOIN private.app_users AS account ON account.id = event.user_id
            WHERE event.user_id = $1
              AND event.id = $2
              AND account.deleted_at IS NULL""",
            account_id,
            event_id,
        )
        row = first_row(rows)
        return None if row is None else security_event_from_row(row)

    async def list_for_account(
        self,
        account_id: UUID,
        limit: int = 100,
    ) -> list[SecurityEventRecord]:
        """Return recent events for one active account in bounded pages."""

        if limit <= 0:
            raise ValueError("limit must be positive")
        rows = await self._database.fetch(
            f"""SELECT {_SECURITY_EVENT_COLUMNS}
            FROM private.security_events AS event
            JOIN private.app_users AS account ON account.id = event.user_id
            WHERE event.user_id = $1
              AND account.deleted_at IS NULL
            ORDER BY event.created_at DESC
            LIMIT $2""",
            account_id,
            limit,
        )
        return [security_event_from_row(as_row(row)) for row in rows]

    async def create(
        self,
        event_type: str,
        outcome: str,
        expires_at: datetime,
        *,
        user_id: UUID | None = None,
        device_id: UUID | None = None,
        network_fingerprint: bytes | None = None,
        details: Mapping[str, object] | None = None,
    ) -> SecurityEventRecord:
        """Record one event, validating optional account/device association in SQL."""

        details_json = json.dumps(
            dict(details or {}),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        rows = await self._database.fetch(
            f"""INSERT INTO private.security_events (
                user_id,
                device_id,
                event_type,
                outcome,
                network_fingerprint,
                details,
                expires_at
            )
            SELECT $1, $2, $3, $4, $5, $6::jsonb, $7
            WHERE ($1::uuid IS NULL OR EXISTS (
                SELECT 1
                FROM private.app_users AS account
                WHERE account.id = $1
                  AND account.deleted_at IS NULL
            ))
              AND ($2::uuid IS NULL OR EXISTS (
                  SELECT 1
                  FROM private.devices AS device
                  WHERE device.id = $2
                    AND ($1::uuid IS NULL OR device.user_id = $1)
              ))
            RETURNING {_SECURITY_EVENT_COLUMNS}""",
            user_id,
            device_id,
            event_type,
            outcome,
            network_fingerprint,
            details_json,
            expires_at,
        )
        return security_event_from_row(required_row(rows))

    async def record(
        self,
        event_type: str,
        outcome: str,
        expires_at: datetime,
        *,
        user_id: UUID | None = None,
        device_id: UUID | None = None,
        network_fingerprint: bytes | None = None,
        details: Mapping[str, object] | None = None,
    ) -> SecurityEventRecord:
        """Compatibility name for callers that describe insertion as recording."""

        return await self.create(
            event_type,
            outcome,
            expires_at,
            user_id=user_id,
            device_id=device_id,
            network_fingerprint=network_fingerprint,
            details=details,
        )

    async def list_by_account(
        self,
        account_id: UUID,
        limit: int = 100,
    ) -> list[SecurityEventRecord]:
        """Compatibility name for callers that use ``by_account`` terminology."""

        return await self.list_for_account(account_id, limit)


class InMemorySecurityEventRepository:
    """Small explicit test-only event store used by the test application."""

    def __init__(self) -> None:
        self._events: list[SecurityEventRecord] = []
        self._lock = threading.Lock()

    @property
    def events(self) -> tuple[SecurityEventRecord, ...]:
        """Return a stable snapshot for focused service and API tests."""

        with self._lock:
            return tuple(self._events)

    async def get_by_id(
        self,
        account_id: UUID,
        event_id: UUID,
    ) -> SecurityEventRecord | None:
        with self._lock:
            return next(
                (
                    event
                    for event in self._events
                    if event.user_id == account_id and event.id == event_id
                ),
                None,
            )

    async def list_for_account(
        self,
        account_id: UUID,
        limit: int = 100,
    ) -> list[SecurityEventRecord]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._lock:
            events = [event for event in self._events if event.user_id == account_id]
        return events[:limit]

    async def create(
        self,
        event_type: str,
        outcome: str,
        expires_at: datetime,
        *,
        user_id: UUID | None = None,
        device_id: UUID | None = None,
        network_fingerprint: bytes | None = None,
        details: Mapping[str, object] | None = None,
    ) -> SecurityEventRecord:
        event = SecurityEventRecord(
            id=uuid4(),
            user_id=user_id,
            device_id=device_id,
            event_type=event_type,
            outcome=outcome,
            network_fingerprint=(
                None if network_fingerprint is None else bytes(network_fingerprint)
            ),
            details=dict(details or {}),
            created_at=datetime.now(UTC),
            expires_at=expires_at,
        )
        with self._lock:
            self._events.append(event)
        return event

    async def record(
        self,
        event_type: str,
        outcome: str,
        expires_at: datetime,
        *,
        user_id: UUID | None = None,
        device_id: UUID | None = None,
        network_fingerprint: bytes | None = None,
        details: Mapping[str, object] | None = None,
    ) -> SecurityEventRecord:
        return await self.create(
            event_type,
            outcome,
            expires_at,
            user_id=user_id,
            device_id=device_id,
            network_fingerprint=network_fingerprint,
            details=details,
        )


# Keep the table-oriented name available to callers.
SecurityEventLogRepository = SecurityEventRepository
