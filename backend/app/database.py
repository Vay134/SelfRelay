"""Async PostgreSQL connection boundary."""

from __future__ import annotations

from typing import Protocol, cast

import asyncpg  # type: ignore[import-untyped]


class _Pool(Protocol):
    async def close(self) -> None: ...

    async def fetch(self, query: str, *parameters: object) -> list[object]: ...

    async def execute(self, query: str, *parameters: object) -> str: ...


class Database:
    """Own an asyncpg pool and forward parameterized queries to it."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url
        self._pool: _Pool | None = None

    @property
    def pool(self) -> _Pool:
        """Return the connected pool or raise when the boundary is unavailable."""

        if self._pool is None:
            raise RuntimeError("database is not connected")
        return self._pool

    async def connect(self) -> None:
        """Create the connection pool once."""

        if self._pool is None:
            self._pool = cast(
                _Pool,
                await asyncpg.create_pool(dsn=self._database_url),
            )

    async def close(self) -> None:
        """Close the pool when one has been created."""

        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        """Fetch rows using asyncpg's positional query parameters."""

        return await self.pool.fetch(query, *parameters)

    async def execute(self, query: str, *parameters: object) -> str:
        """Execute a command using asyncpg's positional query parameters."""

        return await self.pool.execute(query, *parameters)
