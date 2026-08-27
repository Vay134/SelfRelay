"""Repository operations for persistent rate-limit buckets."""

from __future__ import annotations

from datetime import datetime

from .base import RepositoryDatabase, as_row, first_row, required_row
from .models import RateLimitBucketRecord, rate_limit_bucket_from_row

_RATE_LIMIT_BUCKET_COLUMNS = """
    scope,
    bucket_key,
    window_started_at,
    window_expires_at,
    request_count
"""


class RateLimitBucketRepository:
    """Atomically create and increment HMAC-keyed rate-limit buckets."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def get(
        self,
        scope: str,
        bucket_key: bytes,
    ) -> RateLimitBucketRecord | None:
        """Return a bucket whether its current enforcement window has expired."""

        rows = await self._database.fetch(
            f"""SELECT {_RATE_LIMIT_BUCKET_COLUMNS}
            FROM private.rate_limit_buckets
            WHERE scope = $1
              AND bucket_key = $2""",
            scope,
            bucket_key,
        )
        row = first_row(rows)
        return None if row is None else rate_limit_bucket_from_row(row)

    async def get_active(
        self,
        scope: str,
        bucket_key: bytes,
    ) -> RateLimitBucketRecord | None:
        """Return a bucket only while its enforcement window is active."""

        rows = await self._database.fetch(
            f"""SELECT {_RATE_LIMIT_BUCKET_COLUMNS}
            FROM private.rate_limit_buckets
            WHERE scope = $1
              AND bucket_key = $2
              AND window_expires_at > CURRENT_TIMESTAMP""",
            scope,
            bucket_key,
        )
        row = first_row(rows)
        return None if row is None else rate_limit_bucket_from_row(row)

    async def increment(
        self,
        scope: str,
        bucket_key: bytes,
        window_expires_at: datetime,
    ) -> RateLimitBucketRecord:
        """Atomically increment a bucket or begin a new window after expiry."""

        rows = await self._database.fetch(
            f"""INSERT INTO private.rate_limit_buckets (
                scope,
                bucket_key,
                window_expires_at,
                request_count
            )
            VALUES ($1, $2, $3, 1)
            ON CONFLICT (scope, bucket_key) DO UPDATE
            SET window_started_at = CASE
                    WHEN rate_limit_buckets.window_expires_at <= CURRENT_TIMESTAMP
                        THEN CURRENT_TIMESTAMP
                    ELSE rate_limit_buckets.window_started_at
                END,
                window_expires_at = CASE
                    WHEN rate_limit_buckets.window_expires_at <= CURRENT_TIMESTAMP
                        THEN EXCLUDED.window_expires_at
                    ELSE rate_limit_buckets.window_expires_at
                END,
                request_count = CASE
                    WHEN rate_limit_buckets.window_expires_at <= CURRENT_TIMESTAMP
                        THEN 1
                    ELSE rate_limit_buckets.request_count + 1
                END
            RETURNING {_RATE_LIMIT_BUCKET_COLUMNS}""",
            scope,
            bucket_key,
            window_expires_at,
        )
        return rate_limit_bucket_from_row(required_row(rows))

    async def record_request(
        self,
        scope: str,
        bucket_key: bytes,
        window_expires_at: datetime,
    ) -> RateLimitBucketRecord:
        """Compatibility name for callers that describe increments as requests."""

        return await self.increment(scope, bucket_key, window_expires_at)

    async def upsert(
        self,
        scope: str,
        bucket_key: bytes,
        window_expires_at: datetime,
    ) -> RateLimitBucketRecord:
        """Compatibility name for callers focused on the database operation."""

        return await self.increment(scope, bucket_key, window_expires_at)

    async def delete(self, scope: str, bucket_key: bytes) -> bool:
        """Delete one bucket and report whether a row was removed."""

        rows = await self._database.fetch(
            """DELETE FROM private.rate_limit_buckets
            WHERE scope = $1 AND bucket_key = $2
            RETURNING scope""",
            scope,
            bucket_key,
        )
        return bool(rows)

    async def delete_expired(self, limit: int = 100) -> int:
        """Delete at most ``limit`` expired buckets in one atomic statement."""

        if limit <= 0:
            raise ValueError("limit must be positive")
        rows = await self._database.fetch(
            """DELETE FROM private.rate_limit_buckets AS bucket
            WHERE bucket.ctid IN (
                SELECT candidate.ctid
                FROM private.rate_limit_buckets AS candidate
                WHERE candidate.window_expires_at <= CURRENT_TIMESTAMP
                ORDER BY candidate.window_expires_at
                LIMIT $1
            )
            RETURNING bucket.scope, bucket.bucket_key""",
            limit,
        )
        return len([as_row(row) for row in rows])


# Keep the shorter name available to callers that use the table's concept.
RateLimitRepository = RateLimitBucketRepository
