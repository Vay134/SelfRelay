"""Repository operations for persistent rate-limit buckets."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import cast

from .base import (
    RepositoryDatabase,
    TransactionalRepositoryDatabase,
    as_row,
    first_row,
    required_row,
)
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

    async def consume_many(
        self,
        requests: Sequence[tuple[str, bytes, int, timedelta]],
        *,
        now: datetime | None = None,
    ) -> bool:
        """Atomically consume several persistent buckets when all have capacity.

        The rate-limit decision and increments share one transaction.  This is
        important for OTP requests, which consume both an email and a network
        bucket: a rejected request must not consume one bucket while leaving
        the other untouched.
        """

        if not requests:
            raise ValueError("at least one rate-limit bucket is required")
        current = datetime.now(UTC) if now is None else now
        if current.tzinfo is None:
            raise ValueError("rate-limit timestamps must be timezone-aware")
        current = current.astimezone(UTC)
        for scope, bucket_key, limit, window in requests:
            if not 1 <= len(scope) <= 64:
                raise ValueError("rate-limit scopes must be between 1 and 64 characters")
            if len(bucket_key) != 32:
                raise ValueError("rate-limit bucket keys must be SHA-256 digests")
            if limit <= 0 or window <= timedelta(0):
                raise ValueError("rate-limit limits and windows must be valid")

        database = cast(TransactionalRepositoryDatabase, self._database)
        async with database.transaction() as transaction_database:
            states: list[tuple[str, bytes, int, timedelta, datetime | None, int]] = []
            for scope, bucket_key, limit, window in requests:
                rows = await transaction_database.fetch(
                    """SELECT window_expires_at, request_count
                    FROM private.rate_limit_buckets
                    WHERE scope = $1 AND bucket_key = $2
                    FOR UPDATE""",
                    scope,
                    bucket_key,
                )
                row = first_row(rows)
                window_expires_at = (
                    None if row is None else cast(datetime, row["window_expires_at"])
                )
                request_count = 0 if row is None else cast(int, row["request_count"])
                if (
                    window_expires_at is not None
                    and window_expires_at > current
                    and request_count >= limit
                ):
                    return False
                states.append((scope, bucket_key, limit, window, window_expires_at, request_count))

            for scope, bucket_key, _limit, window, window_expires_at, request_count in states:
                if window_expires_at is None or window_expires_at <= current:
                    replacement_expiry = current + window
                    await transaction_database.fetch(
                        f"""INSERT INTO private.rate_limit_buckets (
                            scope,
                            bucket_key,
                            window_started_at,
                            window_expires_at,
                            request_count
                        )
                        VALUES ($1, $2, $3, $4, 1)
                        ON CONFLICT (scope, bucket_key) DO UPDATE
                        SET window_started_at = EXCLUDED.window_started_at,
                            window_expires_at = EXCLUDED.window_expires_at,
                            request_count = EXCLUDED.request_count
                        RETURNING {_RATE_LIMIT_BUCKET_COLUMNS}""",
                        scope,
                        bucket_key,
                        current,
                        replacement_expiry,
                    )
                else:
                    await transaction_database.fetch(
                        """UPDATE private.rate_limit_buckets
                        SET request_count = $3
                        WHERE scope = $1 AND bucket_key = $2""",
                        scope,
                        bucket_key,
                        request_count + 1,
                    )
        return True

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


class PersistentRateLimiter:
    """HMAC-keyed rate limiter backed by ``rate_limit_buckets``."""

    def __init__(
        self,
        repository: RateLimitBucketRepository,
        secret: bytes,
    ) -> None:
        if not secret:
            raise ValueError("rate-limit secret must not be empty")
        self._repository = repository
        self._secret = bytes(secret)

    @property
    def secret(self) -> bytes:
        """Return the configured HMAC key for callers that derive fingerprints."""

        return self._secret

    def fingerprint(self, scope: str, value: str) -> bytes:
        """Derive a scope-separated HMAC bucket key without storing raw input."""

        if not scope:
            raise ValueError("rate-limit scope must not be empty")
        return hmac.new(
            self._secret,
            f"{scope}:{value}".encode(),
            hashlib.sha256,
        ).digest()

    async def allow_many(
        self,
        requests: Sequence[tuple[str, str, int, timedelta]],
        *,
        now: datetime | None = None,
    ) -> bool:
        """Consume all requested buckets only when every bucket has capacity."""

        if not requests:
            raise ValueError("at least one rate-limit bucket is required")
        current = datetime.now(UTC) if now is None else now
        if current.tzinfo is None:
            raise ValueError("rate-limit timestamps must be timezone-aware")
        current = current.astimezone(UTC)
        encoded: list[tuple[str, bytes, int, timedelta]] = []
        for scope, value, limit, window in requests:
            if not scope or limit <= 0 or window <= timedelta(0):
                raise ValueError("rate-limit scope, limit, and window must be valid")
            encoded.append((scope, self.fingerprint(scope, value), limit, window))
        return await self._repository.consume_many(encoded, now=current)
