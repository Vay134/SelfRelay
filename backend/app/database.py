"""Async PostgreSQL connection boundary."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Protocol, cast

import asyncpg  # type: ignore[import-untyped]

from .repositories.base import RepositoryDatabase

DATABASE_OPERATION_TIMEOUT_SECONDS = 5.0


class _Connection(Protocol):
    """Subset of an asyncpg connection used by repository transactions."""

    async def fetch(self, query: str, *parameters: object) -> list[object]: ...

    def transaction(self) -> AbstractAsyncContextManager[object]: ...


class _PoolAcquireContext(Protocol):
    async def __aenter__(self) -> _Connection: ...

    async def __aexit__(
        self, exc_type: object, exc_value: object, traceback: object
    ) -> bool | None: ...


class _Pool(Protocol):
    async def close(self) -> None: ...

    async def fetch(self, query: str, *parameters: object) -> list[object]: ...

    async def execute(self, query: str, *parameters: object) -> str: ...

    def acquire(self) -> _PoolAcquireContext: ...


class BackendUnavailableError(RuntimeError):
    """Raised when the database provider cannot serve a bounded request."""


class Database:
    """Own an asyncpg pool and forward parameterized queries to it."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url
        self._pool: _Pool | None = None

    @property
    def pool(self) -> _Pool:
        """Return the connected pool or raise when the boundary is unavailable."""

        if self._pool is None:
            raise BackendUnavailableError("database is not connected")
        return self._pool

    async def connect(self) -> None:
        """Create the connection pool once."""

        if self._pool is None:
            try:
                self._pool = cast(
                    _Pool,
                    await asyncio.wait_for(
                        asyncpg.create_pool(dsn=self._database_url),
                        timeout=DATABASE_OPERATION_TIMEOUT_SECONDS,
                    ),
                )
            except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, TimeoutError) as error:
                raise BackendUnavailableError from error

    @property
    def is_connected(self) -> bool:
        """Return whether a pool has been created for this database."""

        return self._pool is not None

    async def close(self) -> None:
        """Close the pool when one has been created."""

        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        """Fetch rows using asyncpg's positional query parameters."""

        try:
            return await asyncio.wait_for(
                self.pool.fetch(query, *parameters),
                timeout=DATABASE_OPERATION_TIMEOUT_SECONDS,
            )
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, TimeoutError) as error:
            raise BackendUnavailableError from error

    async def execute(self, query: str, *parameters: object) -> str:
        """Execute a command using asyncpg's positional query parameters."""

        try:
            return await asyncio.wait_for(
                self.pool.execute(query, *parameters),
                timeout=DATABASE_OPERATION_TIMEOUT_SECONDS,
            )
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, TimeoutError) as error:
            raise BackendUnavailableError from error

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[RepositoryDatabase]:
        """Yield a repository database bound to one committed transaction."""

        try:
            async with self.pool.acquire() as connection:
                async with connection.transaction():
                    yield cast(RepositoryDatabase, connection)
        except (asyncpg.PostgresError, asyncpg.InterfaceError, TimeoutError) as error:
            raise BackendUnavailableError from error


__all__ = ["BackendUnavailableError", "DATABASE_OPERATION_TIMEOUT_SECONDS", "Database"]
