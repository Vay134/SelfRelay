from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app import main
from app.config import load_settings

OPERATOR_TOKEN = "operator-test-token"


def _environment() -> dict[str, str]:
    return {
        "APP_ENV": "test",
        "APP_ORIGIN": "http://localhost:5173",
        "API_ORIGIN": "http://localhost:8000",
        "DATABASE_URL": "postgresql://localhost:5432/test",
        "LOG_LEVEL": "INFO",
        "AUTH_ADAPTER": "fake",
        "TURN_ADAPTER": "fake",
        "AVAILABILITY_PROBE_TOKEN": OPERATOR_TOKEN,
    }


class FakeDatabase:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    settings = load_settings(_environment())
    monkeypatch.setattr(main, "load_settings", lambda: settings)
    monkeypatch.setattr(main, "Database", FakeDatabase)
    with TestClient(main.app, base_url="https://localhost:8000") as test_client:
        yield test_client


def test_operator_metrics_requires_the_dedicated_bearer_token(client: TestClient) -> None:
    missing = client.get("/internal/metrics")
    invalid = client.get("/internal/metrics", headers={"Authorization": "Bearer incorrect"})

    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert missing.json() == {"detail": "Authentication required."}
    assert OPERATOR_TOKEN not in missing.text


def test_operator_metrics_returns_only_the_coarse_resource_snapshot(
    client: TestClient,
) -> None:
    response = client.get(
        "/internal/metrics",
        headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "active_sockets": 0,
        "active_signaling_transfers": 0,
        "queued_messages": 0,
        "queued_bytes": 0,
    }
    assert OPERATOR_TOKEN not in response.text
