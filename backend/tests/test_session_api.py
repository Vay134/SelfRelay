from __future__ import annotations

import asyncio
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from uuid import uuid4

import pytest
from fastapi import Response
from fastapi.testclient import TestClient

from app import main
from app.config import load_settings
from app.sessions import SESSION_COOKIE_NAME

APP_ORIGIN = "http://localhost:5173"


def _environment() -> dict[str, str]:
    return {
        "APP_ENV": "test",
        "APP_ORIGIN": APP_ORIGIN,
        "API_ORIGIN": "http://localhost:8000",
        "DATABASE_URL": "postgresql://localhost:5432/test",
        "LOG_LEVEL": "INFO",
        "AUTH_ADAPTER": "fake",
        "TURN_ADAPTER": "fake",
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


def _issue_session(client: TestClient, *, created_at: datetime | None = None) -> tuple[str, str]:
    response = Response()

    async def issue() -> tuple[str, str]:
        created = await main.app.state.session_issuer.issue_for_device(
            uuid4(),
            uuid4(),
            0,
            response=response,
            created_at=created_at,
        )
        return created.token, response.headers["set-cookie"]

    token, set_cookie = asyncio.run(issue())
    client.cookies.set(SESSION_COOKIE_NAME, token)
    return token, set_cookie


def test_credentialed_cors_allows_only_the_configured_origin(client: TestClient) -> None:
    allowed = client.options(
        "/auth/session/current",
        headers={"Origin": APP_ORIGIN, "Access-Control-Request-Method": "GET"},
    )
    assert allowed.status_code == 204
    assert allowed.headers["access-control-allow-origin"] == APP_ORIGIN
    assert allowed.headers["access-control-allow-credentials"] == "true"
    assert "*" not in allowed.headers["access-control-allow-origin"]

    denied = client.options(
        "/auth/session/current",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_session_cookie_has_host_only_security_attributes(client: TestClient) -> None:
    _, header = _issue_session(client)
    parsed = SimpleCookie()
    parsed.load(header)
    morsel = parsed[SESSION_COOKIE_NAME]

    assert morsel["secure"] is True
    assert morsel["httponly"] is True
    assert morsel["samesite"].lower() == "lax"
    assert morsel["path"] == "/"
    assert morsel["domain"] == ""
    assert morsel.value


def test_current_session_authenticates_cookie_then_reissues_csrf(client: TestClient) -> None:
    token, _ = _issue_session(client)
    current = client.get("/auth/session/current", headers={"Origin": APP_ORIGIN})

    assert current.status_code == 200
    body = current.json()
    assert body["authenticated"] is True
    assert body["csrf_token"]
    assert body["csrf_token"] != token
    assert body["session"]["session_id"] == body["session_id"]
    assert "token_hash" not in current.text
    assert "csrf_hash" not in current.text


def test_logout_requires_origin_and_matching_session_csrf(client: TestClient) -> None:
    _issue_session(client)
    current = client.get("/auth/session/current", headers={"Origin": APP_ORIGIN})
    csrf_token = current.json()["csrf_token"]

    missing = client.post("/auth/logout", headers={"Origin": APP_ORIGIN})
    assert missing.status_code == 403
    mismatch = client.post(
        "/auth/logout",
        headers={"Origin": APP_ORIGIN, "X-CSRF-Token": "incorrect"},
    )
    assert mismatch.status_code == 403
    foreign_origin = client.post(
        "/auth/logout",
        headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf_token},
    )
    assert foreign_origin.status_code == 403

    logged_out = client.post(
        "/auth/logout",
        headers={"Origin": APP_ORIGIN, "X-CSRF-Token": csrf_token},
    )
    assert logged_out.status_code == 200
    assert "Max-Age=0" in logged_out.headers["set-cookie"]
    assert "Domain=" not in logged_out.headers["set-cookie"]
    assert client.get("/auth/session/current", headers={"Origin": APP_ORIGIN}).status_code == 401


def test_session_list_has_only_safe_public_fields(client: TestClient) -> None:
    token, _ = _issue_session(client)
    response = client.get("/auth/sessions", headers={"Origin": APP_ORIGIN})

    assert response.status_code == 200
    body = response.json()
    assert len(body["sessions"]) == 1
    public = body["sessions"][0]
    assert set(public) == {
        "session_id",
        "device_id",
        "created_at",
        "last_seen_at",
        "idle_expires_at",
        "absolute_expires_at",
        "revoked_at",
        "revocation_reason",
    }
    assert token not in response.text
    assert "token_hash" not in response.text
    assert "csrf_hash" not in response.text
    assert "supabase" not in response.text.casefold()


def test_expired_session_is_not_authenticated(client: TestClient) -> None:
    _, _ = _issue_session(client, created_at=datetime.now(UTC) - timedelta(days=100))

    response = client.get("/auth/session/current", headers={"Origin": APP_ORIGIN})

    assert response.status_code == 401
