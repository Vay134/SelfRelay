from __future__ import annotations

import asyncio
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from app import availability, main
from app.config import load_settings

DATABASE_URL = "postgresql://localhost:5432/test"
PROBE_TOKEN = "availability-test-token"
SECRET_DATABASE_ERROR = "password=do-not-disclose host=db.internal"


def _environment(**overrides: str) -> dict[str, str]:
    values = {
        "APP_ENV": "test",
        "APP_ORIGIN": "http://localhost:5173",
        "API_ORIGIN": "http://localhost:8000",
        "DATABASE_URL": DATABASE_URL,
        "LOG_LEVEL": "INFO",
        "AUTH_ADAPTER": "fake",
        "TURN_ADAPTER": "fake",
        "AVAILABILITY_PROBE_TOKEN": PROBE_TOKEN,
    }
    values.update(overrides)
    return values


class FakeDatabase:
    def __init__(self, *, connected: bool = True, error: Exception | None = None) -> None:
        self.is_connected = connected
        self.error = error
        self.connect_calls = 0
        self.queries: list[str] = []

    async def connect(self) -> None:
        self.connect_calls += 1
        self.is_connected = True

    async def close(self) -> None:
        self.is_connected = False

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        del parameters
        self.queries.append(query)
        if self.error is not None:
            raise self.error
        return [cast(Any, {"probe": 1})]


class SlowDatabase(FakeDatabase):
    async def fetch(self, query: str, *parameters: object) -> list[object]:
        del parameters
        self.queries.append(query)
        await asyncio.sleep(3600)
        return []


@contextmanager
def _client(
    monkeypatch: pytest.MonkeyPatch,
    database: FakeDatabase,
    **environment_overrides: str,
) -> Generator[TestClient, None, None]:
    settings = load_settings(_environment(**environment_overrides))
    monkeypatch.setattr(main, "load_settings", lambda: settings)
    monkeypatch.setattr(main, "Database", lambda _url: database)
    with TestClient(main.app, base_url="https://localhost:8000") as client:
        yield client


def test_wake_is_public_and_returns_only_safe_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    with _client(monkeypatch, database) as client:
        response = client.get("/availability/wake")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert database.queries == []


def test_readiness_connects_and_runs_one_safe_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase(connected=False)
    with _client(monkeypatch, database) as client:
        response = client.get("/availability/readiness")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    assert database.connect_calls == 1
    assert database.queries == [availability.DATABASE_PROBE_QUERY]


def test_readiness_returns_safe_terminal_failure_for_database_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase(error=RuntimeError(SECRET_DATABASE_ERROR))
    with _client(monkeypatch, database) as client:
        response = client.get("/availability/readiness")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert SECRET_DATABASE_ERROR not in response.text
    assert "password" not in response.text
    assert "db.internal" not in response.text


def test_readiness_has_a_short_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = SlowDatabase()
    monkeypatch.setattr(availability, "AVAILABILITY_DATABASE_TIMEOUT_SECONDS", 0.01)
    with _client(monkeypatch, database) as client:
        response = client.get("/availability/readiness")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def test_probe_requires_the_dedicated_bearer_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    with _client(monkeypatch, database) as client:
        missing = client.get("/availability/probe")
        invalid = client.get(
            "/availability/probe",
            headers={"Authorization": "Bearer incorrect"},
        )

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert missing.json() == {"detail": availability.AVAILABILITY_AUTHORIZATION_ERROR}
    assert PROBE_TOKEN not in missing.text
    assert database.queries == []


def test_probe_authenticates_then_performs_database_backed_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    with _client(monkeypatch, database) as client:
        response = client.get(
            "/availability/probe",
            headers={"Authorization": f"Bearer {PROBE_TOKEN}"},
        )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert database.queries == [availability.DATABASE_PROBE_QUERY]
    assert PROBE_TOKEN not in response.text


def test_probe_failure_is_authenticated_but_stays_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase(error=RuntimeError(SECRET_DATABASE_ERROR))
    with _client(monkeypatch, database) as client:
        response = client.get(
            "/availability/probe",
            headers={"Authorization": f"Bearer {PROBE_TOKEN}"},
        )

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert SECRET_DATABASE_ERROR not in response.text
    assert PROBE_TOKEN not in response.text
