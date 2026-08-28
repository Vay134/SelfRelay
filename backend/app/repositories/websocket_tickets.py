"""Repository operations for single-use WebSocket tickets."""

from __future__ import annotations

import threading
from collections.abc import Awaitable
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from .base import (
    RepositoryDatabase,
    TransactionalRepositoryDatabase,
    first_row,
    required_row,
)
from .models import WebSocketTicketRecord, websocket_ticket_from_row

_WEBSOCKET_TICKET_COLUMNS = """
    id,
    session_id,
    token_hash,
    created_at,
    expires_at,
    consumed_at
"""
_WEBSOCKET_TICKET_SELECT_COLUMNS = """
    ticket.id,
    ticket.session_id,
    ticket.token_hash,
    ticket.created_at,
    ticket.expires_at,
    ticket.consumed_at
"""


class WebSocketTicketRepository:
    """Persist short-lived tickets bound to usable account sessions."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def get_by_id(
        self,
        account_id: UUID,
        ticket_id: UUID,
    ) -> WebSocketTicketRecord | None:
        """Return one ticket only when its session belongs to the account."""

        rows = await self._database.fetch(
            f"""SELECT {_WEBSOCKET_TICKET_SELECT_COLUMNS}
            FROM private.websocket_tickets AS ticket
            JOIN private.app_sessions AS app_session
              ON app_session.id = ticket.session_id
            JOIN private.app_users AS account
              ON account.id = app_session.user_id
            WHERE account.id = $1
              AND ticket.id = $2
              AND account.deleted_at IS NULL""",
            account_id,
            ticket_id,
        )
        row = first_row(rows)
        return None if row is None else websocket_ticket_from_row(row)

    async def get_by_token_hash(
        self,
        account_id: UUID,
        token_hash: bytes,
    ) -> WebSocketTicketRecord | None:
        """Return a currently usable, unconsumed ticket for one account."""

        rows = await self._database.fetch(
            f"""SELECT {_WEBSOCKET_TICKET_SELECT_COLUMNS}
            FROM private.websocket_tickets AS ticket
            JOIN private.app_sessions AS app_session
              ON app_session.id = ticket.session_id
            JOIN private.app_users AS account
              ON account.id = app_session.user_id
            JOIN private.devices AS device
              ON device.id = app_session.device_id
             AND device.user_id = account.id
            WHERE account.id = $1
              AND ticket.token_hash = $2
              AND ticket.consumed_at IS NULL
              AND ticket.expires_at > CURRENT_TIMESTAMP
              AND account.deleted_at IS NULL
              AND app_session.revoked_at IS NULL
              AND app_session.idle_expires_at > CURRENT_TIMESTAMP
              AND app_session.absolute_expires_at > CURRENT_TIMESTAMP
              AND app_session.epoch = account.device_epoch
              AND device.status = 'active'
              AND device.epoch = account.device_epoch""",
            account_id,
            token_hash,
        )
        row = first_row(rows)
        return None if row is None else websocket_ticket_from_row(row)

    async def create(
        self,
        account_id: UUID,
        session_id: UUID,
        token_hash: bytes,
        expires_at: datetime,
    ) -> WebSocketTicketRecord:
        """Create a ticket only for an active, current-epoch session."""

        rows = await self._database.fetch(
            f"""INSERT INTO private.websocket_tickets (
                session_id,
                token_hash,
                expires_at
            )
            SELECT app_session.id, $3, $4
            FROM private.app_sessions AS app_session
            JOIN private.app_users AS account ON account.id = app_session.user_id
            JOIN private.devices AS device
              ON device.id = app_session.device_id
             AND device.user_id = account.id
            WHERE account.id = $1
              AND app_session.id = $2
              AND account.deleted_at IS NULL
              AND app_session.revoked_at IS NULL
              AND app_session.idle_expires_at > CURRENT_TIMESTAMP
              AND app_session.absolute_expires_at > CURRENT_TIMESTAMP
              AND app_session.epoch = account.device_epoch
              AND device.status = 'active'
              AND device.epoch = account.device_epoch
            RETURNING {_WEBSOCKET_TICKET_COLUMNS}""",
            account_id,
            session_id,
            token_hash,
            expires_at,
        )
        return websocket_ticket_from_row(required_row(rows))

    async def consume(
        self,
        account_id: UUID,
        token_hash: bytes,
    ) -> WebSocketTicketRecord | None:
        """Atomically consume one unexpired ticket identified by its token hash."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            rows = await transaction_database.fetch(
                f"""UPDATE private.websocket_tickets AS ticket
                SET consumed_at = CURRENT_TIMESTAMP
                WHERE ticket.token_hash = $2
                  AND ticket.consumed_at IS NULL
                  AND ticket.expires_at > CURRENT_TIMESTAMP
                  AND EXISTS (
                      SELECT 1
                      FROM private.app_sessions AS app_session
                      JOIN private.app_users AS account
                        ON account.id = app_session.user_id
                      JOIN private.devices AS device
                        ON device.id = app_session.device_id
                       AND device.user_id = account.id
                      WHERE app_session.id = ticket.session_id
                        AND account.id = $1
                        AND account.deleted_at IS NULL
                        AND app_session.revoked_at IS NULL
                        AND app_session.idle_expires_at > CURRENT_TIMESTAMP
                        AND app_session.absolute_expires_at > CURRENT_TIMESTAMP
                        AND app_session.epoch = account.device_epoch
                        AND device.status = 'active'
                        AND device.epoch = account.device_epoch
                  )
                RETURNING {_WEBSOCKET_TICKET_COLUMNS}""",
                account_id,
                token_hash,
            )
        row = first_row(rows)
        return None if row is None else websocket_ticket_from_row(row)

    async def consume_for_socket(
        self,
        token_hash: bytes,
    ) -> WebSocketTicketRecord | None:
        """Atomically consume a ticket after validating its bound session.

        The ticket is the only credential available during a browser
        WebSocket handshake, so this operation intentionally does not require
        an account identifier.  The session and device joins still enforce
        account ownership and current-epoch authentication before returning.
        """

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            rows = await transaction_database.fetch(
                f"""UPDATE private.websocket_tickets AS ticket
                SET consumed_at = CURRENT_TIMESTAMP
                WHERE ticket.token_hash = $1
                  AND ticket.consumed_at IS NULL
                  AND ticket.expires_at > CURRENT_TIMESTAMP
                  AND EXISTS (
                      SELECT 1
                      FROM private.app_sessions AS app_session
                      JOIN private.app_users AS account
                        ON account.id = app_session.user_id
                      JOIN private.devices AS device
                        ON device.id = app_session.device_id
                       AND device.user_id = account.id
                      WHERE app_session.id = ticket.session_id
                        AND account.deleted_at IS NULL
                        AND app_session.revoked_at IS NULL
                        AND app_session.idle_expires_at > CURRENT_TIMESTAMP
                        AND app_session.absolute_expires_at > CURRENT_TIMESTAMP
                        AND app_session.epoch = account.device_epoch
                        AND device.status = 'active'
                        AND device.epoch = account.device_epoch
                  )
                RETURNING {_WEBSOCKET_TICKET_COLUMNS}""",
                token_hash,
            )
        row = first_row(rows)
        return None if row is None else websocket_ticket_from_row(row)

    async def consume_by_id(
        self,
        account_id: UUID,
        ticket_id: UUID,
    ) -> WebSocketTicketRecord | None:
        """Atomically consume one unexpired ticket identified by its UUID."""

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            rows = await transaction_database.fetch(
                f"""UPDATE private.websocket_tickets AS ticket
                SET consumed_at = CURRENT_TIMESTAMP
                WHERE ticket.id = $2
                  AND ticket.consumed_at IS NULL
                  AND ticket.expires_at > CURRENT_TIMESTAMP
                  AND EXISTS (
                      SELECT 1
                      FROM private.app_sessions AS app_session
                      JOIN private.app_users AS account
                        ON account.id = app_session.user_id
                      JOIN private.devices AS device
                        ON device.id = app_session.device_id
                       AND device.user_id = account.id
                      WHERE app_session.id = ticket.session_id
                        AND account.id = $1
                        AND account.deleted_at IS NULL
                        AND app_session.revoked_at IS NULL
                        AND app_session.idle_expires_at > CURRENT_TIMESTAMP
                        AND app_session.absolute_expires_at > CURRENT_TIMESTAMP
                        AND app_session.epoch = account.device_epoch
                        AND device.status = 'active'
                        AND device.epoch = account.device_epoch
                  )
                RETURNING {_WEBSOCKET_TICKET_COLUMNS}""",
                account_id,
                ticket_id,
            )
        row = first_row(rows)
        return None if row is None else websocket_ticket_from_row(row)

    async def consume_by_token_hash(
        self,
        account_id: UUID,
        token_hash: bytes,
    ) -> WebSocketTicketRecord | None:
        """Compatibility name for callers that identify tickets by token hash."""

        return await self.consume(account_id, token_hash)


# Keep the common spelling available to callers that do not capitalize acronyms.
WebsocketTicketRepository = WebSocketTicketRepository


class InMemoryWebSocketTicketRepository:
    """Explicit test-only ticket store with atomic one-time consumption."""

    def __init__(self, session_repository: object | None = None) -> None:
        self._session_repository = session_repository
        self._records: dict[UUID, WebSocketTicketRecord] = {}
        self._accounts: dict[UUID, UUID] = {}
        self._by_token_hash: dict[bytes, UUID] = {}
        self._lock = threading.Lock()

    async def get_by_id(
        self,
        account_id: UUID,
        ticket_id: UUID,
    ) -> WebSocketTicketRecord | None:
        """Return one ticket only when it belongs to the requested account."""

        with self._lock:
            record = self._records.get(ticket_id)
            if record is None or self._accounts.get(ticket_id) != account_id:
                return None
            return record

    async def get_by_token_hash(
        self,
        account_id: UUID,
        token_hash: bytes,
    ) -> WebSocketTicketRecord | None:
        """Return a currently usable, unconsumed ticket for one account."""

        record, owner = self._record_for_token(token_hash)
        if record is None or owner != account_id or not self._is_usable(record):
            return None
        if not await self._session_is_current(owner, record.session_id):
            return None
        return record

    async def create(
        self,
        account_id: UUID,
        session_id: UUID,
        token_hash: bytes,
        expires_at: datetime,
    ) -> WebSocketTicketRecord:
        """Create a ticket bound to one currently usable test session."""

        current = datetime.now(UTC)
        if expires_at.tzinfo is None or expires_at.astimezone(UTC) <= current:
            raise ValueError("ticket expiry must be in the future")
        normalized_hash = bytes(token_hash)
        if len(normalized_hash) != 32:
            raise ValueError("ticket hashes must contain 32 bytes")
        if not await self._session_is_current(account_id, session_id):
            raise RuntimeError("session is unavailable")
        record = WebSocketTicketRecord(
            id=uuid4(),
            session_id=session_id,
            token_hash=normalized_hash,
            created_at=current,
            expires_at=expires_at.astimezone(UTC),
            consumed_at=None,
        )
        with self._lock:
            if normalized_hash in self._by_token_hash:
                raise ValueError("ticket hash is already registered")
            self._records[record.id] = record
            self._accounts[record.id] = account_id
            self._by_token_hash[normalized_hash] = record.id
        return record

    async def consume(
        self,
        account_id: UUID,
        token_hash: bytes,
    ) -> WebSocketTicketRecord | None:
        """Atomically consume one ticket for an account."""

        return await self._consume(token_hash, account_id=account_id)

    async def consume_for_socket(
        self,
        token_hash: bytes,
    ) -> WebSocketTicketRecord | None:
        """Atomically consume one ticket for a WebSocket handshake."""

        return await self._consume(token_hash)

    async def consume_by_id(
        self,
        account_id: UUID,
        ticket_id: UUID,
    ) -> WebSocketTicketRecord | None:
        """Atomically consume one account-owned ticket by identifier."""

        with self._lock:
            record = self._records.get(ticket_id)
            owner = self._accounts.get(ticket_id)
            if record is None or owner != account_id:
                return None
            token_hash = record.token_hash
        return await self._consume(token_hash, account_id=account_id)

    async def consume_by_token_hash(
        self,
        account_id: UUID,
        token_hash: bytes,
    ) -> WebSocketTicketRecord | None:
        """Compatibility name for callers that identify tickets by token hash."""

        return await self.consume(account_id, token_hash)

    async def _consume(
        self,
        token_hash: bytes,
        *,
        account_id: UUID | None = None,
    ) -> WebSocketTicketRecord | None:
        record, owner = self._record_for_token(token_hash)
        if (
            record is None
            or owner is None
            or (account_id is not None and owner != account_id)
            or not self._is_usable(record)
        ):
            return None
        if not await self._session_is_current(owner, record.session_id):
            return None
        current = datetime.now(UTC)
        with self._lock:
            latest = self._records.get(record.id)
            if (
                latest is None
                or latest.consumed_at is not None
                or latest.expires_at <= current
                or self._accounts.get(record.id) != owner
            ):
                return None
            consumed = replace(latest, consumed_at=current)
            self._records[latest.id] = consumed
            return consumed

    def _record_for_token(
        self,
        token_hash: bytes,
    ) -> tuple[WebSocketTicketRecord | None, UUID | None]:
        with self._lock:
            ticket_id = self._by_token_hash.get(bytes(token_hash))
            if ticket_id is None:
                return None, None
            return self._records.get(ticket_id), self._accounts.get(ticket_id)

    @staticmethod
    def _is_usable(record: WebSocketTicketRecord) -> bool:
        return record.consumed_at is None and record.expires_at > datetime.now(UTC)

    async def _session_is_current(self, account_id: UUID, session_id: UUID) -> bool:
        if self._session_repository is None:
            return True
        lookup = getattr(self._session_repository, "find_current_by_id", None)
        if not callable(lookup):
            return True
        result = lookup(session_id)
        session = await cast(Awaitable[object | None], result)
        return session is not None and getattr(session, "user_id", None) == account_id


# Keep both spellings available to callers that do not capitalize acronyms.
InMemoryWebsocketTicketRepository = InMemoryWebSocketTicketRepository
