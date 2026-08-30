"""Bounded retention cleanup for private application records."""

from __future__ import annotations

from typing import cast

from .base import RepositoryDatabase, TransactionalRepositoryDatabase

DEFAULT_CLEANUP_BATCH_SIZE = 100
MAX_CLEANUP_BATCH_SIZE = 1_000


def _validate_batch_size(batch_size: int) -> None:
    """Reject unbounded or nonsensical cleanup requests before querying."""

    if not 0 < batch_size <= MAX_CLEANUP_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {MAX_CLEANUP_BATCH_SIZE}")


async def _delete_batch(
    database: RepositoryDatabase,
    query: str,
    batch_size: int,
) -> int:
    """Delete one bounded batch and count its returned rows."""

    rows = await database.fetch(query, batch_size)
    return len(rows)


_SESSION_CLEANUP_QUERY = """DELETE FROM private.app_sessions AS session
    WHERE session.ctid IN (
        SELECT candidate.ctid
        FROM private.app_sessions AS candidate
        WHERE (
            candidate.revoked_at IS NOT NULL
            AND candidate.revoked_at <= CURRENT_TIMESTAMP - INTERVAL '7 days'
        )
        OR (
            candidate.revoked_at IS NULL
            AND LEAST(candidate.idle_expires_at, candidate.absolute_expires_at)
                <= CURRENT_TIMESTAMP - INTERVAL '7 days'
        )
        ORDER BY COALESCE(candidate.revoked_at, candidate.absolute_expires_at)
        LIMIT $1
    )
    RETURNING session.id"""

_CHALLENGE_CLEANUP_QUERY = """DELETE FROM private.device_challenges AS challenge
    WHERE challenge.ctid IN (
        SELECT candidate.ctid
        FROM private.device_challenges AS candidate
        WHERE candidate.consumed_at IS NOT NULL
           OR candidate.expires_at <= CURRENT_TIMESTAMP
        ORDER BY COALESCE(candidate.consumed_at, candidate.expires_at)
        LIMIT $1
    )
    RETURNING challenge.id"""

_LINKING_OTP_CLEANUP_QUERY = """DELETE FROM private.device_linking_otps AS otp
    WHERE otp.ctid IN (
        SELECT candidate.ctid
        FROM private.device_linking_otps AS candidate
        WHERE candidate.status IN ('consumed', 'expired')
           OR candidate.expires_at <= CURRENT_TIMESTAMP
        ORDER BY COALESCE(candidate.consumed_at, candidate.expires_at)
        LIMIT $1
    )
    RETURNING otp.id"""

_TRANSFER_CLEANUP_QUERY = """DELETE FROM private.transfer_requests AS transfer
    WHERE transfer.ctid IN (
        SELECT candidate.ctid
        FROM private.transfer_requests AS candidate
        WHERE candidate.status IN (
            'completed', 'rejected', 'expired', 'cancelled', 'failed'
        )
          AND COALESCE(candidate.completed_at, candidate.created_at)
                <= CURRENT_TIMESTAMP - INTERVAL '30 days'
        ORDER BY COALESCE(candidate.completed_at, candidate.created_at)
        LIMIT $1
    )
    RETURNING transfer.id"""

_TICKET_CLEANUP_QUERY = """DELETE FROM private.websocket_tickets AS ticket
    WHERE ticket.ctid IN (
        SELECT candidate.ctid
        FROM private.websocket_tickets AS candidate
        WHERE candidate.consumed_at IS NOT NULL
           OR candidate.expires_at <= CURRENT_TIMESTAMP
        ORDER BY COALESCE(candidate.consumed_at, candidate.expires_at)
        LIMIT $1
    )
    RETURNING ticket.id"""

_SECURITY_EVENT_CLEANUP_QUERY = """DELETE FROM private.security_events AS event
    WHERE event.ctid IN (
        SELECT candidate.ctid
        FROM private.security_events AS candidate
        WHERE candidate.expires_at <= CURRENT_TIMESTAMP
        ORDER BY candidate.expires_at
        LIMIT $1
    )
    RETURNING event.id"""

_RATE_LIMIT_CLEANUP_QUERY = """DELETE FROM private.rate_limit_buckets AS bucket
    WHERE bucket.ctid IN (
        SELECT candidate.ctid
        FROM private.rate_limit_buckets AS candidate
        WHERE candidate.window_expires_at <= CURRENT_TIMESTAMP
        ORDER BY candidate.window_expires_at
        LIMIT $1
    )
    RETURNING bucket.scope, bucket.bucket_key"""


class ExpiryCleanupRepository:
    """Delete expired or retained records in small, committed batches."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def cleanup_expired(
        self,
        batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE,
    ) -> dict[str, int]:
        """Clean every retention-managed table in one transaction."""

        _validate_batch_size(batch_size)
        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            return {
                "app_sessions": await _delete_batch(
                    transaction_database,
                    _SESSION_CLEANUP_QUERY,
                    batch_size,
                ),
                "device_challenges": await _delete_batch(
                    transaction_database,
                    _CHALLENGE_CLEANUP_QUERY,
                    batch_size,
                ),
                "device_linking_otps": await _delete_batch(
                    transaction_database,
                    _LINKING_OTP_CLEANUP_QUERY,
                    batch_size,
                ),
                "transfer_requests": await _delete_batch(
                    transaction_database,
                    _TRANSFER_CLEANUP_QUERY,
                    batch_size,
                ),
                "websocket_tickets": await _delete_batch(
                    transaction_database,
                    _TICKET_CLEANUP_QUERY,
                    batch_size,
                ),
                "security_events": await _delete_batch(
                    transaction_database,
                    _SECURITY_EVENT_CLEANUP_QUERY,
                    batch_size,
                ),
                "rate_limit_buckets": await _delete_batch(
                    transaction_database,
                    _RATE_LIMIT_CLEANUP_QUERY,
                    batch_size,
                ),
            }

    async def cleanup(
        self,
        batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE,
    ) -> dict[str, int]:
        """Compatibility name for callers that run the retention job."""

        return await self.cleanup_expired(batch_size)

    async def run(
        self,
        batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE,
    ) -> dict[str, int]:
        """Compatibility name for scheduler integrations."""

        return await self.cleanup_expired(batch_size)

    async def cleanup_all(
        self,
        batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE,
    ) -> dict[str, int]:
        """Compatibility name for callers that distinguish one table from all tables."""

        return await self.cleanup_expired(batch_size)

    async def _cleanup_one(self, query: str, batch_size: int) -> int:
        """Run one table cleanup with the same transaction guarantee as cleanup_all."""

        _validate_batch_size(batch_size)
        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            return await _delete_batch(transaction_database, query, batch_size)

    async def cleanup_sessions(self, batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE) -> int:
        """Delete old revoked or expired sessions in one bounded batch."""

        return await self._cleanup_one(_SESSION_CLEANUP_QUERY, batch_size)

    async def cleanup_challenges(self, batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE) -> int:
        """Delete consumed or expired device challenges in one bounded batch."""

        return await self._cleanup_one(_CHALLENGE_CLEANUP_QUERY, batch_size)

    async def cleanup_device_linking_otps(
        self,
        batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE,
    ) -> int:
        """Delete consumed or expired device-linking codes in one bounded batch."""

        return await self._cleanup_one(_LINKING_OTP_CLEANUP_QUERY, batch_size)

    async def cleanup_transfers(self, batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE) -> int:
        """Delete terminal transfer records past their retention deadline."""

        return await self._cleanup_one(_TRANSFER_CLEANUP_QUERY, batch_size)

    async def cleanup_tickets(self, batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE) -> int:
        """Delete consumed or expired WebSocket tickets in one bounded batch."""

        return await self._cleanup_one(_TICKET_CLEANUP_QUERY, batch_size)

    async def cleanup_security_events(
        self,
        batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE,
    ) -> int:
        """Delete security events after their explicit retention deadline."""

        return await self._cleanup_one(_SECURITY_EVENT_CLEANUP_QUERY, batch_size)

    async def cleanup_rate_limits(
        self,
        batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE,
    ) -> int:
        """Delete rate-limit buckets after their enforcement window."""

        return await self._cleanup_one(_RATE_LIMIT_CLEANUP_QUERY, batch_size)


# Keep a concise name available to callers that use generic cleanup terminology.
CleanupRepository = ExpiryCleanupRepository
