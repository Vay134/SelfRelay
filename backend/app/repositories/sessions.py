"""Repository operations for account-owned application sessions."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from .base import RepositoryDatabase, as_row, first_row, required_row
from .models import SessionRecord, session_from_row

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


class SessionRepository:
    """Persist opaque sessions while keeping every operation account-scoped."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def get_by_id(self, account_id: UUID, session_id: UUID) -> SessionRecord | None:
        """Return one session only when it belongs to the requested account."""

        rows = await self._database.fetch(
            f"""SELECT {_SESSION_COLUMNS}
            FROM private.app_sessions
            WHERE user_id = $1 AND id = $2""",
            account_id,
            session_id,
        )
        row = first_row(rows)
        return None if row is None else session_from_row(row)

    async def get_by_token_hash(
        self,
        account_id: UUID,
        token_hash: bytes,
    ) -> SessionRecord | None:
        """Return a currently usable session owned by the requested account."""

        rows = await self._database.fetch(
            f"""SELECT {_SESSION_COLUMNS}
            FROM private.app_sessions
            WHERE user_id = $1
              AND token_hash = $2
              AND revoked_at IS NULL
              AND idle_expires_at > CURRENT_TIMESTAMP
              AND absolute_expires_at > CURRENT_TIMESTAMP
              AND EXISTS (
                  SELECT 1
                  FROM private.app_users AS account
                  WHERE account.id = private.app_sessions.user_id
                    AND account.deleted_at IS NULL
                    AND account.device_epoch = private.app_sessions.epoch
              )
              AND EXISTS (
                  SELECT 1
                  FROM private.devices AS device
                  WHERE device.user_id = private.app_sessions.user_id
                    AND device.id = private.app_sessions.device_id
                    AND device.status = 'active'
                    AND device.epoch = private.app_sessions.epoch
              )""",
            account_id,
            token_hash,
        )
        row = first_row(rows)
        return None if row is None else session_from_row(row)

    async def find_by_token_hash(self, token_hash: bytes) -> SessionRecord | None:
        """Return a usable session after validating account and device state.

        The cookie does not contain an account identifier, so this lookup is
        intentionally keyed only by the SHA-256 token digest.  The joins keep
        a revoked device, deleted account, or stale account epoch from
        authenticating even when its session row still exists.
        """

        rows = await self._database.fetch(
            """SELECT
                session.id,
                session.user_id,
                session.device_id,
                session.token_hash,
                session.csrf_hash,
                session.epoch,
                session.created_at,
                session.last_seen_at,
                session.idle_expires_at,
                session.absolute_expires_at,
                session.revoked_at,
                session.revocation_reason
            FROM private.app_sessions AS session
            JOIN private.app_users AS account
              ON account.id = session.user_id
            JOIN private.devices AS device
              ON device.user_id = session.user_id
             AND device.id = session.device_id
            WHERE session.token_hash = $1
              AND session.revoked_at IS NULL
              AND session.idle_expires_at > CURRENT_TIMESTAMP
              AND session.absolute_expires_at > CURRENT_TIMESTAMP
              AND account.deleted_at IS NULL
              AND account.device_epoch = session.epoch
              AND device.status = 'active'
              AND device.epoch = session.epoch""",
            token_hash,
        )
        row = first_row(rows)
        return None if row is None else session_from_row(row)

    async def find_current_by_id(self, session_id: UUID) -> SessionRecord | None:
        """Return one currently usable session by its identifier.

        This lookup is used after a single-use WebSocket ticket has been
        atomically consumed.  The joins keep a revoked device, deleted
        account, or stale account epoch from admitting the socket.
        """

        rows = await self._database.fetch(
            """SELECT
                session.id,
                session.user_id,
                session.device_id,
                session.token_hash,
                session.csrf_hash,
                session.epoch,
                session.created_at,
                session.last_seen_at,
                session.idle_expires_at,
                session.absolute_expires_at,
                session.revoked_at,
                session.revocation_reason
            FROM private.app_sessions AS session
            JOIN private.app_users AS account
              ON account.id = session.user_id
            JOIN private.devices AS device
              ON device.user_id = session.user_id
             AND device.id = session.device_id
            WHERE session.id = $1
              AND session.revoked_at IS NULL
              AND session.idle_expires_at > CURRENT_TIMESTAMP
              AND session.absolute_expires_at > CURRENT_TIMESTAMP
              AND account.deleted_at IS NULL
              AND account.device_epoch = session.epoch
              AND device.status = 'active'
              AND device.epoch = session.epoch""",
            session_id,
        )
        row = first_row(rows)
        return None if row is None else session_from_row(row)

    async def list_for_account(self, account_id: UUID) -> list[SessionRecord]:
        """Return all sessions belonging to one account, newest first."""

        rows = await self._database.fetch(
            f"""SELECT {_SESSION_COLUMNS}
            FROM private.app_sessions
            WHERE user_id = $1
            ORDER BY created_at DESC""",
            account_id,
        )
        return [session_from_row(as_row(row)) for row in rows]

    async def create(
        self,
        account_id: UUID,
        device_id: UUID,
        token_hash: bytes,
        csrf_hash: bytes,
        epoch: int,
        idle_expires_at: datetime,
        absolute_expires_at: datetime,
    ) -> SessionRecord:
        """Create a session only for an owned, active, current-epoch device."""

        rows = await self._database.fetch(
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
            WHERE account.id = $1
              AND account.deleted_at IS NULL
              AND device.id = $2
              AND device.status = 'active'
              AND device.epoch = account.device_epoch
              AND $5 = account.device_epoch
            RETURNING {_SESSION_COLUMNS}""",
            account_id,
            device_id,
            token_hash,
            csrf_hash,
            epoch,
            idle_expires_at,
            absolute_expires_at,
        )
        return session_from_row(required_row(rows))

    async def touch_last_seen(
        self,
        account_id: UUID,
        session_id: UUID,
    ) -> SessionRecord | None:
        """Update activity only for an account-owned, non-revoked session."""

        rows = await self._database.fetch(
            f"""UPDATE private.app_sessions
            SET last_seen_at = CURRENT_TIMESTAMP,
                idle_expires_at = LEAST(
                    CURRENT_TIMESTAMP + interval '30 days',
                    absolute_expires_at
                )
            WHERE user_id = $1
              AND id = $2
              AND revoked_at IS NULL
              AND idle_expires_at > CURRENT_TIMESTAMP
              AND absolute_expires_at > CURRENT_TIMESTAMP
              AND EXISTS (
                  SELECT 1
                  FROM private.app_users AS account
                  WHERE account.id = private.app_sessions.user_id
                    AND account.deleted_at IS NULL
                    AND account.device_epoch = private.app_sessions.epoch
              )
              AND EXISTS (
                  SELECT 1
                  FROM private.devices AS device
                  WHERE device.user_id = private.app_sessions.user_id
                    AND device.id = private.app_sessions.device_id
                    AND device.status = 'active'
                    AND device.epoch = private.app_sessions.epoch
              )
            RETURNING {_SESSION_COLUMNS}""",
            account_id,
            session_id,
        )
        row = first_row(rows)
        return None if row is None else session_from_row(row)

    async def replace_csrf_hash(
        self,
        account_id: UUID,
        session_id: UUID,
        csrf_hash: bytes,
    ) -> SessionRecord | None:
        """Replace a session's CSRF digest without returning the raw value."""

        rows = await self._database.fetch(
            f"""UPDATE private.app_sessions
            SET csrf_hash = $3
            WHERE user_id = $1
              AND id = $2
              AND revoked_at IS NULL
              AND idle_expires_at > CURRENT_TIMESTAMP
              AND absolute_expires_at > CURRENT_TIMESTAMP
              AND EXISTS (
                  SELECT 1
                  FROM private.app_users AS account
                  WHERE account.id = private.app_sessions.user_id
                    AND account.deleted_at IS NULL
                    AND account.device_epoch = private.app_sessions.epoch
              )
              AND EXISTS (
                  SELECT 1
                  FROM private.devices AS device
                  WHERE device.user_id = private.app_sessions.user_id
                    AND device.id = private.app_sessions.device_id
                    AND device.status = 'active'
                    AND device.epoch = private.app_sessions.epoch
              )
            RETURNING {_SESSION_COLUMNS}""",
            account_id,
            session_id,
            csrf_hash,
        )
        row = first_row(rows)
        return None if row is None else session_from_row(row)

    async def revoke(
        self,
        account_id: UUID,
        session_id: UUID,
        reason: str = "logout",
    ) -> SessionRecord | None:
        """Revoke one account-owned session without exposing other accounts."""

        rows = await self._database.fetch(
            f"""UPDATE private.app_sessions
            SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP),
                revocation_reason = $3
            WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL
            RETURNING {_SESSION_COLUMNS}""",
            account_id,
            session_id,
            reason,
        )
        row = first_row(rows)
        return None if row is None else session_from_row(row)

    async def revoke_by_token_hash(
        self,
        account_id: UUID,
        token_hash: bytes,
        reason: str = "logout",
    ) -> SessionRecord | None:
        """Revoke one account-owned session identified by its token hash."""

        rows = await self._database.fetch(
            f"""UPDATE private.app_sessions
            SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP),
                revocation_reason = $3
            WHERE user_id = $1 AND token_hash = $2 AND revoked_at IS NULL
            RETURNING {_SESSION_COLUMNS}""",
            account_id,
            token_hash,
            reason,
        )
        row = first_row(rows)
        return None if row is None else session_from_row(row)

    async def revoke_for_device(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "device_revoked",
    ) -> int:
        """Revoke all active sessions for one account-owned device."""

        rows = await self._database.fetch(
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
        return len(rows)

    async def revoke_for_account(
        self,
        account_id: UUID,
        reason: str = "account_cleanup",
    ) -> int:
        """Revoke every active session for an account in one statement."""

        rows = await self._database.fetch(
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

    async def list_by_account(self, account_id: UUID) -> list[SessionRecord]:
        """Compatibility name for callers that use ``by_account`` terminology."""

        return await self.list_for_account(account_id)
