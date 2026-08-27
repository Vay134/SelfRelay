"""Repository operations for single-use WebSocket tickets."""

from __future__ import annotations

from datetime import datetime
from typing import cast
from uuid import UUID

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
