import asyncio
from unittest.mock import AsyncMock

import pytest

from app.database import Database


def test_connect_uses_configured_url_and_forwards_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = AsyncMock()
    pool.fetch.return_value = ["row"]
    pool.execute.return_value = "INSERT 0 1"
    create_pool = AsyncMock(return_value=pool)
    monkeypatch.setattr("app.database.asyncpg.create_pool", create_pool)

    async def exercise() -> None:
        database = Database("postgresql://localhost:5432/test")

        await database.connect()
        rows = await database.fetch("SELECT * FROM files WHERE id = $1", "file-1")
        result = await database.execute(
            "UPDATE files SET name = $1 WHERE id = $2", "updated.txt", "file-1"
        )

        assert rows == ["row"]
        assert result == "INSERT 0 1"
        create_pool.assert_awaited_once_with(dsn="postgresql://localhost:5432/test")
        pool.fetch.assert_awaited_once_with("SELECT * FROM files WHERE id = $1", "file-1")
        pool.execute.assert_awaited_once_with(
            "UPDATE files SET name = $1 WHERE id = $2", "updated.txt", "file-1"
        )

    asyncio.run(exercise())


def test_connect_is_idempotent_and_close_releases_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = AsyncMock()
    create_pool = AsyncMock(return_value=pool)
    monkeypatch.setattr("app.database.asyncpg.create_pool", create_pool)

    async def exercise() -> None:
        database = Database("postgresql://localhost:5432/test")

        await database.connect()
        await database.connect()
        await database.close()
        await database.close()

        create_pool.assert_awaited_once()
        pool.close.assert_awaited_once()
        with pytest.raises(RuntimeError, match="not connected"):
            _ = database.pool

    asyncio.run(exercise())
