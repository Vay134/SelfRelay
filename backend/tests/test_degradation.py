from __future__ import annotations

import asyncio
from typing import Any, cast

import asyncpg  # type: ignore[import-untyped]
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import database as database_module
from app import main
from app.database import BackendUnavailableError, Database
from app.main import BACKEND_UNAVAILABLE_MESSAGE, _backend_unavailable
from app.metrics import RuntimeMetrics

DATABASE_URL = "postgresql://localhost:5432/unreachable"
SECRET_DETAIL = "password=super-secret host=10.0.0.4"


class UnreachablePool:
    async def fetch(self, query: str, *parameters: object) -> list[object]:
        raise asyncpg.PostgresConnectionError(SECRET_DETAIL)

    async def execute(self, query: str, *parameters: object) -> str:
        raise OSError(SECRET_DETAIL)


class SlowPool:
    async def fetch(self, query: str, *parameters: object) -> list[object]:
        await asyncio.sleep(3600)
        return []


class UnconnectableDatabase(Database):
    async def connect(self) -> None:
        raise BackendUnavailableError("database is not connected")


def _database_with_pool(pool: object) -> Database:
    database = Database(DATABASE_URL)
    database._pool = cast(Any, pool)
    return database


def _degradation_client() -> TestClient:
    application = FastAPI()

    @application.get("/boom")
    async def boom() -> dict[str, str]:
        raise asyncpg.PostgresConnectionError(SECRET_DETAIL)

    application.state.metrics = RuntimeMetrics()
    for error in (asyncpg.PostgresError, asyncpg.InterfaceError):
        application.add_exception_handler(error, _backend_unavailable)
    return TestClient(application, raise_server_exceptions=False)


def test_an_unconnected_database_reports_a_terminal_error() -> None:
    async def exercise() -> None:
        database = Database(DATABASE_URL)

        assert not database.is_connected
        with pytest.raises(BackendUnavailableError):
            await database.fetch("SELECT 1")

    asyncio.run(exercise())


def test_database_failures_surface_as_one_bounded_backend_error() -> None:
    async def exercise() -> None:
        database = _database_with_pool(UnreachablePool())

        with pytest.raises(BackendUnavailableError):
            await database.fetch("SELECT 1")
        with pytest.raises(BackendUnavailableError):
            await database.execute("SELECT 1")

    asyncio.run(exercise())


def test_a_slow_database_times_out_instead_of_hanging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(database_module, "DATABASE_OPERATION_TIMEOUT_SECONDS", 0.01)

    async def exercise() -> None:
        database = _database_with_pool(SlowPool())

        with pytest.raises(BackendUnavailableError):
            await database.fetch("SELECT 1")

    asyncio.run(exercise())


def test_provider_failures_answer_with_a_safe_terminal_response() -> None:
    client = _degradation_client()

    response = client.get("/boom")

    assert response.status_code == 503
    assert response.json() == {"detail": BACKEND_UNAVAILABLE_MESSAGE}
    assert "password" not in response.text
    assert "10.0.0.4" not in response.text


def test_health_reports_unavailable_while_the_database_cannot_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        main.app.state,
        "database",
        UnconnectableDatabase(DATABASE_URL),
        raising=False,
    )

    response = TestClient(main.app).get("/health")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def test_health_reports_ok_once_the_database_is_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        main.app.state,
        "database",
        _database_with_pool(UnreachablePool()),
        raising=False,
    )

    response = TestClient(main.app).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
