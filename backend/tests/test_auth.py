from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app import main
from app.adapters import FakeAuthGateway
from app.auth import (
    OTP_START_EMAIL_LIMIT,
    OTP_START_NETWORK_LIMIT,
    InMemoryAccountStore,
    RateLimiter,
    normalize_email,
)
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


class FakeDatabase:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    settings = load_settings(_environment())
    monkeypatch.setattr(main, "load_settings", lambda: settings)
    monkeypatch.setattr(main, "Database", FakeDatabase)
    with TestClient(main.app) as test_client:
        yield test_client


def test_normalize_email_is_unicode_aware_and_provider_neutral() -> None:
    assert normalize_email("  Alice@Example.TEST ") == "alice@example.test"
    assert normalize_email("Straße@Example.TEST") == "strasse@example.test"


def test_rate_limiter_uses_distinct_hmac_buckets_and_expires() -> None:
    limiter = RateLimiter(secret=b"rate-limit-secret")
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)

    assert limiter.fingerprint("email", "a@example.test") != limiter.fingerprint(
        "network", "a@example.test"
    )
    assert limiter.allow("email", "a@example.test", 1, timedelta(minutes=1), now=issued_at)
    assert not limiter.allow(
        "email", "a@example.test", 1, timedelta(minutes=1), now=issued_at + timedelta(seconds=1)
    )
    assert limiter.allow(
        "email", "a@example.test", 1, timedelta(minutes=1), now=issued_at + timedelta(minutes=1)
    )


def test_otp_start_has_same_contract_for_known_and_unknown_email(client: TestClient) -> None:
    first = client.post("/auth/otp/start", json={"email": "known@example.test"})
    assert first.status_code == 202
    gateway = main.app.state.auth_gateway
    assert isinstance(gateway, FakeAuthGateway)
    otp = gateway.otp_for("known@example.test")
    verified = client.post(
        "/auth/otp/verify",
        json={"email": "known@example.test", "otp": otp},
    )
    assert verified.status_code == 200

    known = client.post("/auth/otp/start", json={"email": "known@example.test"})
    unknown = client.post("/auth/otp/start", json={"email": "new@example.test"})

    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    assert "set-cookie" not in known.headers


def test_otp_routes_normalize_before_provider_and_do_not_leak_otp(client: TestClient) -> None:
    started = client.post("/auth/otp/start", json={"email": " Alice@Example.TEST "})
    assert started.status_code == 202
    gateway = main.app.state.auth_gateway
    assert isinstance(gateway, FakeAuthGateway)
    assert gateway.requested_emails == ("alice@example.test",)
    otp = gateway.otp_for("alice@example.test")

    invalid = client.post(
        "/auth/otp/verify",
        json={"email": " alice@example.test ", "otp": "000000"},
    )
    assert invalid.status_code == 400
    assert invalid.json() == {"detail": "The email or one-time code is invalid."}
    assert otp not in invalid.text

    verified = client.post(
        "/auth/otp/verify",
        json={"email": " alice@example.test ", "otp": otp},
    )
    assert verified.status_code == 200
    body = verified.json()
    assert body["bootstrap_token"]
    assert otp not in verified.text
    assert "set-cookie" not in verified.headers
    assert "session" not in body


def test_otp_start_applies_email_and_network_limits_before_gateway(client: TestClient) -> None:
    gateway = main.app.state.auth_gateway
    assert isinstance(gateway, FakeAuthGateway)

    for _ in range(OTP_START_EMAIL_LIMIT):
        response = client.post("/auth/otp/start", json={"email": "repeat@example.test"})
        assert response.status_code == 202
    blocked_email = client.post("/auth/otp/start", json={"email": "repeat@example.test"})
    assert blocked_email.status_code == 429
    assert len(gateway.requested_emails) == OTP_START_EMAIL_LIMIT

    remaining_network_requests = OTP_START_NETWORK_LIMIT - OTP_START_EMAIL_LIMIT
    for index in range(remaining_network_requests):
        response = client.post(
            "/auth/otp/start",
            json={"email": f"network-{index}@example.test"},
        )
        assert response.status_code == 202
    blocked_network = client.post(
        "/auth/otp/start",
        json={"email": "network-blocked@example.test"},
    )
    assert blocked_network.status_code == 429


def test_invalid_unknown_and_wrong_otps_have_the_same_generic_response(client: TestClient) -> None:
    unknown = client.post(
        "/auth/otp/verify",
        json={"email": "unknown@example.test", "otp": "123456"},
    )
    client.post("/auth/otp/start", json={"email": "known@example.test"})
    wrong = client.post(
        "/auth/otp/verify",
        json={"email": "known@example.test", "otp": "123456"},
    )
    assert unknown.status_code == wrong.status_code == 400
    assert unknown.json() == wrong.json()


def test_in_memory_account_store_retrieves_the_same_account() -> None:
    async def exercise() -> None:
        store = InMemoryAccountStore()
        user_id = uuid4()
        created_at = datetime(2026, 1, 1, tzinfo=UTC)
        first = await store.get_or_create(user_id, "a@example.test", created_at=created_at)
        second = await store.get_or_create(user_id, "a@example.test", created_at=created_at)
        assert first == second

    import asyncio

    asyncio.run(exercise())
