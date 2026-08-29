from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import Response
from fastapi.testclient import TestClient

from app import main
from app.adapters import (
    DisabledTurnCredentialProvider,
    FakeTurnCredentialProvider,
    TurnCredentialProviderError,
    TurnCredentialRequest,
    TurnCredentials,
)
from app.config import load_settings
from app.repositories.models import DeviceRecord, TransferRequestRecord
from app.sessions import SESSION_COOKIE_NAME, CreatedSession
from app.turn import (
    TURN_CREDENTIAL_TTL_SECONDS,
    TURN_PROVIDER_UNAVAILABLE_MESSAGE,
    TURN_RATE_LIMIT_MESSAGE,
    TURN_UNAVAILABLE_MESSAGE,
)

APP_ORIGIN = "http://localhost:5173"


def _environment(**overrides: str) -> dict[str, str]:
    values = {
        "APP_ENV": "test",
        "APP_ORIGIN": APP_ORIGIN,
        "API_ORIGIN": "http://localhost:8000",
        "DATABASE_URL": "postgresql://localhost:5432/test",
        "LOG_LEVEL": "INFO",
        "AUTH_ADAPTER": "fake",
        "TURN_ADAPTER": "fake",
    }
    values.update(overrides)
    return values


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


@pytest.fixture
def disabled_turn_client(monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    settings = load_settings(_environment(TURN_ADAPTER="disabled"))
    monkeypatch.setattr(main, "load_settings", lambda: settings)
    monkeypatch.setattr(main, "Database", FakeDatabase)
    with TestClient(main.app, base_url="https://localhost:8000") as test_client:
        yield test_client


def _create_device(client: TestClient, account_id: UUID) -> DeviceRecord:
    device_id = uuid4()

    async def create() -> DeviceRecord:
        return cast(
            DeviceRecord,
            await main.app.state.device_repository.create(
                account_id,
                0,
                str(device_id),
                b"spki",
                hashlib.sha256(device_id.bytes).digest(),
            ),
        )

    return asyncio.run(create())


def _issue_session(client: TestClient, account_id: UUID, device_id: UUID) -> CreatedSession:
    response = Response()

    async def issue() -> CreatedSession:
        return cast(
            CreatedSession,
            await main.app.state.session_issuer.issue_for_device(
                account_id,
                device_id,
                0,
                response=response,
            ),
        )

    created = asyncio.run(issue())
    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE_NAME, created.token)
    return created


def _create_transfer(
    account_id: UUID,
    sender_device_id: UUID,
    recipient_device_id: UUID,
    *,
    expires_at: datetime | None = None,
    accepted: bool = False,
) -> UUID:
    async def create() -> UUID:
        repository = main.app.state.transfer_repository
        record = cast(
            TransferRequestRecord,
            await repository.create(
                account_id,
                sender_device_id,
                recipient_device_id,
                1,
                expires_at or datetime.now(UTC) + timedelta(minutes=5),
            ),
        )
        if accepted:
            assert await repository.accept(account_id, record.id, recipient_device_id)
        return record.id

    return asyncio.run(create())


def _issue(client: TestClient, transfer_id: UUID, csrf_secret: str) -> httpx.Response:
    return client.post(
        f"/auth/transfers/{transfer_id}/turn-credentials",
        headers={"Origin": APP_ORIGIN, "X-CSRF-Token": csrf_secret},
    )


def test_turn_credentials_require_an_accepted_transfer_and_active_participant(
    client: TestClient,
) -> None:
    account_id = uuid4()
    sender = _create_device(client, account_id)
    recipient = _create_device(client, account_id)
    outsider = _create_device(client, account_id)
    session = _issue_session(client, account_id, sender.id)
    provider = cast(FakeTurnCredentialProvider, main.app.state.turn_credential_provider)

    offered_id = _create_transfer(account_id, sender.id, recipient.id)
    offered = _issue(client, offered_id, session.csrf_secret)
    assert offered.status_code == 409
    assert offered.json() == {"detail": TURN_UNAVAILABLE_MESSAGE}
    assert provider.requests == ()

    accepted_id = _create_transfer(account_id, sender.id, recipient.id, accepted=True)
    accepted = _issue(client, accepted_id, session.csrf_secret)
    assert accepted.status_code == 200
    body = cast(dict[str, object], accepted.json())
    assert set(body) == {"ice_servers", "expires_at"}
    ice_servers = cast(list[dict[str, object]], body["ice_servers"])
    assert len(ice_servers) == 1
    assert ice_servers[0]["urls"] == [
        "stun:turn.test.invalid",
        "turn:turn.test.invalid?transport=udp",
    ]
    assert isinstance(ice_servers[0]["username"], str)
    assert isinstance(ice_servers[0]["credential"], str)
    assert provider.requests[-1].transfer_id == str(accepted_id)
    assert provider.requests[-1].ttl_seconds == TURN_CREDENTIAL_TTL_SECONDS

    rejected_id = _create_transfer(account_id, sender.id, recipient.id)
    assert asyncio.run(
        main.app.state.transfer_repository.reject(account_id, rejected_id, recipient.id)
    )
    rejected = _issue(client, rejected_id, session.csrf_secret)
    assert rejected.status_code == 409

    cancelled_id = _create_transfer(account_id, sender.id, recipient.id, accepted=True)
    assert asyncio.run(
        main.app.state.transfer_repository.cancel(account_id, cancelled_id, sender.id)
    )
    cancelled = _issue(client, cancelled_id, session.csrf_secret)
    assert cancelled.status_code == 409

    expired_id = _create_transfer(
        account_id,
        sender.id,
        recipient.id,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    expired = _issue(client, expired_id, session.csrf_secret)
    assert expired.status_code == 409

    outsider_session = _issue_session(client, account_id, outsider.id)
    non_participant = _issue(client, accepted_id, outsider_session.csrf_secret)
    assert non_participant.status_code == 409
    assert len(provider.requests) == 1


def test_turn_credentials_reject_foreign_and_unauthenticated_requests(client: TestClient) -> None:
    account_id = uuid4()
    sender = _create_device(client, account_id)
    recipient = _create_device(client, account_id)
    accepted_id = _create_transfer(account_id, sender.id, recipient.id, accepted=True)

    client.cookies.clear()
    unauthenticated = client.post(
        f"/auth/transfers/{accepted_id}/turn-credentials",
        headers={"Origin": APP_ORIGIN},
    )
    assert unauthenticated.status_code == 401

    foreign_account_id = uuid4()
    foreign_device = _create_device(client, foreign_account_id)
    foreign_session = _issue_session(client, foreign_account_id, foreign_device.id)
    foreign = _issue(client, accepted_id, foreign_session.csrf_secret)
    assert foreign.status_code == 409


def test_turn_credential_issuance_is_rate_limited_per_transfer(client: TestClient) -> None:
    account_id = uuid4()
    sender = _create_device(client, account_id)
    recipient = _create_device(client, account_id)
    session = _issue_session(client, account_id, sender.id)
    transfer_id = _create_transfer(account_id, sender.id, recipient.id, accepted=True)
    provider = cast(FakeTurnCredentialProvider, main.app.state.turn_credential_provider)

    for _ in range(6):
        response = _issue(client, transfer_id, session.csrf_secret)
        assert response.status_code == 200

    limited = _issue(client, transfer_id, session.csrf_secret)
    assert limited.status_code == 429
    assert limited.json() == {"detail": TURN_RATE_LIMIT_MESSAGE}
    assert len(provider.requests) == 6


def test_turn_provider_outage_returns_a_terminal_error_without_provider_detail(
    client: TestClient,
) -> None:
    account_id = uuid4()
    sender = _create_device(client, account_id)
    recipient = _create_device(client, account_id)
    session = _issue_session(client, account_id, sender.id)
    transfer_id = _create_transfer(account_id, sender.id, recipient.id, accepted=True)

    class OutageProvider:
        async def issue_credentials(self, request: TurnCredentialRequest) -> TurnCredentials:
            raise TurnCredentialProviderError("cloudflare token cf-secret-token rejected")

    main.app.state.turn_credential_service._provider = OutageProvider()

    response = _issue(client, transfer_id, session.csrf_secret)

    assert response.status_code == 503
    assert response.json() == {"detail": TURN_PROVIDER_UNAVAILABLE_MESSAGE}
    assert "cf-secret-token" not in response.text


def test_disabled_turn_adapter_returns_generic_provider_unavailable_response(
    disabled_turn_client: TestClient,
) -> None:
    account_id = uuid4()
    sender = _create_device(disabled_turn_client, account_id)
    recipient = _create_device(disabled_turn_client, account_id)
    session = _issue_session(disabled_turn_client, account_id, sender.id)
    transfer_id = _create_transfer(account_id, sender.id, recipient.id, accepted=True)

    assert isinstance(main.app.state.turn_credential_provider, DisabledTurnCredentialProvider)

    response = _issue(disabled_turn_client, transfer_id, session.csrf_secret)

    assert response.status_code == 503
    assert response.json() == {"detail": TURN_PROVIDER_UNAVAILABLE_MESSAGE}
