import pytest
from fastapi.testclient import TestClient

from app import main
from app.config import load_settings


def _environment() -> dict[str, str]:
    return {
        "APP_ENV": "test",
        "APP_ORIGIN": "http://localhost:5173",
        "API_ORIGIN": "http://localhost:8000",
        "DATABASE_URL": "postgresql://localhost:5432/test",
        "LOG_LEVEL": "INFO",
        "AUTH_ADAPTER": "fake",
        "TURN_ADAPTER": "fake",
    }


def test_lifespan_connects_and_closes_database(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeDatabase:
        def __init__(self, database_url: str) -> None:
            self.database_url = database_url
            self.connected = False
            self.closed = False
            databases.append(self)

        async def connect(self) -> None:
            self.connected = True

        async def close(self) -> None:
            self.closed = True

    settings = load_settings(_environment())
    databases: list[FakeDatabase] = []

    monkeypatch.setattr(main, "load_settings", lambda: settings)
    monkeypatch.setattr(main, "Database", FakeDatabase)

    with TestClient(main.app):
        assert len(databases) == 1
        assert databases[0].database_url == settings.database_url
        assert databases[0].connected
        assert not databases[0].closed

    assert databases[0].closed
