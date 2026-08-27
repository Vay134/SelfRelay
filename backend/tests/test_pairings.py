from __future__ import annotations

import base64
from collections.abc import Generator
from typing import cast
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from app import main
from app.adapters import FakeAuthGateway
from app.auth import OtpBootstrapService
from app.config import load_settings
from app.device_crypto import fingerprint_public_key, signed_message
from app.pairings import PAIRING_REQUEST_MESSAGE
from app.repositories.models import AccountRecord, PairingRequestRecord
from app.repositories.pairings import InMemoryPairingRequestRepository
from app.sessions import SESSION_COOKIE_NAME, hash_secret

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


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _new_key() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key


def _sign(private_key: ec.EllipticCurvePrivateKey, payload: dict[str, object]) -> str:
    der_signature = private_key.sign(signed_message(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _bootstrap(client: TestClient, email: str) -> dict[str, object]:
    started = client.post("/auth/otp/start", json={"email": email})
    assert started.status_code == 202
    gateway = main.app.state.auth_gateway
    assert isinstance(gateway, FakeAuthGateway)
    verified = client.post(
        "/auth/otp/verify",
        json={"email": email, "otp": gateway.otp_for(email)},
    )
    assert verified.status_code == 200
    return cast(dict[str, object], verified.json())


def _register(client: TestClient, email: str) -> dict[str, object]:
    private_key, public_key = _new_key()
    bootstrap = _bootstrap(client, email)
    challenge = client.post(
        "/auth/devices/registration-challenge",
        headers={"Origin": APP_ORIGIN},
        json={
            "bootstrap_token": bootstrap["bootstrap_token"],
            "public_key": _b64(public_key),
            "label": "Laptop",
        },
    )
    assert challenge.status_code == 200
    challenge_body = cast(dict[str, object], challenge.json())
    completed = client.post(
        "/auth/devices/register",
        headers={"Origin": APP_ORIGIN},
        json={
            "challenge_id": challenge_body["challenge_id"],
            "signature": _sign(private_key, cast(dict[str, object], challenge_body["payload"])),
        },
    )
    assert completed.status_code == 200
    return cast(dict[str, object], completed.json())


def test_pairing_request_creation_returns_code_and_only_hashes_it_at_rest(
    client: TestClient,
) -> None:
    email = "alice@example.test"
    _register(client, email)
    old_cookie = client.cookies.get(SESSION_COOKIE_NAME)
    _, public_key = _new_key()
    fingerprint = fingerprint_public_key(public_key)

    response = client.post(
        "/auth/pairing/requests",
        headers={"Origin": APP_ORIGIN},
        json={
            "email": email,
            "public_key": _b64(public_key),
            "fingerprint": _b64(fingerprint),
            "label": "New browser",
        },
    )

    assert response.status_code == 202
    body = cast(dict[str, object], response.json())
    assert body["message"] == PAIRING_REQUEST_MESSAGE
    assert body["status"] == "pending"
    assert body["fingerprint"] == _b64(fingerprint)
    assert isinstance(body["comparison_code"], str)
    assert body["comparison_code"].isdigit()
    assert len(body["comparison_code"]) == 6
    assert len(_b64(base64.urlsafe_b64decode(cast(str, body["request_nonce"]) + "=="))) == 43
    assert client.cookies.get(SESSION_COOKIE_NAME) == old_cookie

    request_id = cast(str, body["request_id"])
    repository = main.app.state.pairing_repository
    account = awaitable_get_account(main.app.state.auth_service, email)
    record = awaitable_get_pairing(repository, account.id, request_id)
    assert isinstance(record, PairingRequestRecord)
    assert record.comparison_code_hash == hash_secret(body["comparison_code"])
    assert body["comparison_code"] not in record.comparison_code_hash.hex()
    assert record.requested_public_key_spki == public_key
    assert record.requested_fingerprint == fingerprint
    assert record.expires_at > record.created_at


def test_pairing_request_rejects_missing_or_invalid_values(client: TestClient) -> None:
    missing_key = client.post(
        "/auth/pairing/request",
        headers={"Origin": APP_ORIGIN},
        json={"email": "alice@example.test"},
    )
    assert missing_key.status_code == 400
    assert missing_key.json() == {"detail": "The pairing request is invalid."}

    invalid_key = client.post(
        "/auth/pairing/request",
        headers={"Origin": APP_ORIGIN},
        json={
            "email": "alice@example.test",
            "public_key": "not-base64!",
        },
    )
    assert invalid_key.status_code == 400
    assert invalid_key.json() == {"detail": "The pairing request is invalid."}

    _, public_key = _new_key()
    wrong_fingerprint = b"x" * 32
    mismatched_fingerprint = client.post(
        "/auth/pairing/request",
        headers={"Origin": APP_ORIGIN},
        json={
            "email": "alice@example.test",
            "public_key": _b64(public_key),
            "fingerprint": _b64(wrong_fingerprint),
        },
    )
    assert mismatched_fingerprint.status_code == 400
    assert mismatched_fingerprint.json() == {"detail": "The pairing request is invalid."}


def test_known_and_unknown_pairing_requests_have_the_same_public_contract(
    client: TestClient,
) -> None:
    email = "known@example.test"
    _register(client, email)
    _, known_key = _new_key()
    _, unknown_key = _new_key()
    headers = {"Origin": APP_ORIGIN}

    known = client.post(
        "/auth/pairing/request",
        headers=headers,
        json={"email": email, "public_key": _b64(known_key)},
    )
    unknown = client.post(
        "/auth/pairing/request",
        headers=headers,
        json={"email": "unknown@example.test", "public_key": _b64(unknown_key)},
    )

    assert known.status_code == unknown.status_code == 202
    known_body = cast(dict[str, object], known.json())
    unknown_body = cast(dict[str, object], unknown.json())
    assert known_body.keys() == unknown_body.keys()
    assert known_body["message"] == unknown_body["message"] == PAIRING_REQUEST_MESSAGE
    assert known_body["status"] == unknown_body["status"] == "pending"
    assert isinstance(unknown_body["request_id"], str)
    assert isinstance(unknown_body["comparison_code"], str)


def awaitable_get_account(auth_service: OtpBootstrapService, email: str) -> AccountRecord:
    """Synchronous test helper for the async account store."""

    import asyncio

    account = asyncio.run(auth_service.account_store.get_by_email(email))
    assert account is not None
    return account


def awaitable_get_pairing(
    repository: InMemoryPairingRequestRepository,
    account_id: UUID,
    request_id: str,
) -> PairingRequestRecord | None:
    """Synchronous test helper for the async pairing store."""

    import asyncio

    return asyncio.run(repository.get_by_id(account_id, UUID(request_id)))
