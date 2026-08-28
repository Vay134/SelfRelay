from __future__ import annotations

import base64
import secrets
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
from app.device_crypto import (
    fingerprint_public_key,
    pairing_approval_message,
    pairing_approval_payload,
    signed_message,
)
from app.pairings import PAIRING_REQUEST_MESSAGE
from app.repositories.devices import InMemoryDeviceRepository
from app.repositories.models import AccountRecord, DeviceRecord, PairingRequestRecord
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


def _sign_pairing(
    private_key: ec.EllipticCurvePrivateKey,
    payload: dict[str, object],
) -> str:
    der_signature = private_key.sign(
        pairing_approval_message(payload),
        ec.ECDSA(hashes.SHA256()),
    )
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


def _register(
    client: TestClient,
    email: str,
    *,
    private_key: ec.EllipticCurvePrivateKey | None = None,
    public_key: bytes | None = None,
) -> dict[str, object]:
    if private_key is None or public_key is None:
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


def awaitable_get_device(
    repository: InMemoryDeviceRepository,
    account_id: UUID,
    device_id: str,
) -> DeviceRecord | None:
    """Synchronous test helper for the async device store."""

    import asyncio

    return asyncio.run(repository.get_by_id(account_id, UUID(device_id)))


def test_trusted_device_lists_and_approves_exact_requested_key(client: TestClient) -> None:
    approving_private_key, approving_public_key = _new_key()
    registered = _register(
        client,
        "pairing-owner@example.test",
        private_key=approving_private_key,
        public_key=approving_public_key,
    )
    _, requested_public_key = _new_key()
    created = client.post(
        "/auth/pairing/request",
        headers={"Origin": APP_ORIGIN},
        json={
            "email": "pairing-owner@example.test",
            "public_key": _b64(requested_public_key),
            "label": "New browser",
        },
    )
    assert created.status_code == 202
    created_body = cast(dict[str, object], created.json())

    listed = client.get("/auth/pairing/requests", headers={"Origin": APP_ORIGIN})
    assert listed.status_code == 200
    listed_body = cast(dict[str, object], listed.json())
    requests = cast(list[dict[str, object]], listed_body["requests"])
    assert len(requests) == 1
    assert requests[0]["requested_label"] == "New browser"
    assert requests[0]["requested_fingerprint"] == _b64(
        fingerprint_public_key(requested_public_key)
    )
    assert "comparison_code" not in listed.text
    assert _b64(requested_public_key) not in listed.text

    account_id = UUID(cast(str, registered["account_id"]))
    device_body = cast(dict[str, object], registered["device"])
    approving_device = awaitable_get_device(
        main.app.state.device_repository,
        account_id,
        cast(str, device_body["device_id"]),
    )
    assert approving_device is not None
    account = awaitable_get_account(main.app.state.auth_service, "pairing-owner@example.test")
    record = awaitable_get_pairing(
        main.app.state.pairing_repository,
        account.id,
        cast(str, created_body["request_id"]),
    )
    assert record is not None
    approval_nonce = secrets.token_bytes(32)
    approval_payload = pairing_approval_payload(
        record,
        account,
        approving_device,
        approval_nonce=approval_nonce,
    )
    approved = client.post(
        f"/auth/pairing/requests/{created_body['request_id']}/approve",
        headers={
            "Origin": APP_ORIGIN,
            "X-CSRF-Token": cast(str, registered["csrf_token"]),
        },
        json={
            "comparison_code": created_body["comparison_code"],
            "approval_nonce": _b64(approval_nonce),
            "signature": _sign_pairing(approving_private_key, approval_payload),
        },
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    stored = awaitable_get_pairing(
        main.app.state.pairing_repository,
        account.id,
        cast(str, created_body["request_id"]),
    )
    assert stored is not None
    assert stored.status == "approved"
    assert stored.approved_by_device_id == approving_device.id
    assert stored.approval_signature is not None

    replay = client.post(
        f"/auth/pairing/requests/{created_body['request_id']}/approve",
        headers={
            "Origin": APP_ORIGIN,
            "X-CSRF-Token": cast(str, registered["csrf_token"]),
        },
        json={
            "comparison_code": created_body["comparison_code"],
            "approval_nonce": _b64(approval_nonce),
            "signature": _sign_pairing(approving_private_key, approval_payload),
        },
    )
    assert replay.status_code == 401
    assert client.get("/auth/pairing/requests").json() == {"requests": []}


def test_pairing_code_attempts_and_signature_binding_reject_tampering(
    client: TestClient,
) -> None:
    approving_private_key, approving_public_key = _new_key()
    registered = _register(
        client,
        "pairing-tamper@example.test",
        private_key=approving_private_key,
        public_key=approving_public_key,
    )
    _, requested_public_key = _new_key()
    created = client.post(
        "/auth/pairing/request",
        headers={"Origin": APP_ORIGIN},
        json={
            "email": "pairing-tamper@example.test",
            "public_key": _b64(requested_public_key),
        },
    )
    created_body = cast(dict[str, object], created.json())
    account_id = UUID(cast(str, registered["account_id"]))
    account = awaitable_get_account(main.app.state.auth_service, "pairing-tamper@example.test")
    device_body = cast(dict[str, object], registered["device"])
    device = awaitable_get_device(
        main.app.state.device_repository,
        account_id,
        cast(str, device_body["device_id"]),
    )
    assert device is not None
    record = awaitable_get_pairing(
        main.app.state.pairing_repository,
        account.id,
        cast(str, created_body["request_id"]),
    )
    assert record is not None
    approval_nonce = secrets.token_bytes(32)
    payload = pairing_approval_payload(record, account, device, approval_nonce=approval_nonce)
    altered = dict(payload)
    altered["requested_fingerprint"] = _b64(b"x" * 32)
    tampered = client.post(
        f"/auth/pairing/requests/{created_body['request_id']}/approve",
        headers={
            "Origin": APP_ORIGIN,
            "X-CSRF-Token": cast(str, registered["csrf_token"]),
        },
        json={
            "comparison_code": created_body["comparison_code"],
            "approval_nonce": _b64(approval_nonce),
            "signature": _sign_pairing(approving_private_key, altered),
        },
    )
    assert tampered.status_code == 401
    after_tampered = awaitable_get_pairing(
        main.app.state.pairing_repository,
        account.id,
        cast(str, created_body["request_id"]),
    )
    assert after_tampered is not None
    assert after_tampered.status == "pending"

    wrong_code = client.post(
        f"/auth/pairing/requests/{created_body['request_id']}/approve",
        headers={
            "Origin": APP_ORIGIN,
            "X-CSRF-Token": cast(str, registered["csrf_token"]),
        },
        json={
            "comparison_code": "000000",
            "approval_nonce": _b64(approval_nonce),
            "signature": _sign_pairing(approving_private_key, payload),
        },
    )
    assert wrong_code.status_code == 401
    after_wrong_code = awaitable_get_pairing(
        main.app.state.pairing_repository,
        account.id,
        cast(str, created_body["request_id"]),
    )
    assert after_wrong_code is not None
    assert after_wrong_code.attempt_count == 2


def test_rejected_pairing_is_terminal_and_requires_csrf(client: TestClient) -> None:
    registered = _register(client, "pairing-reject@example.test")
    _, requested_public_key = _new_key()
    created = client.post(
        "/auth/pairing/request",
        headers={"Origin": APP_ORIGIN},
        json={
            "email": "pairing-reject@example.test",
            "public_key": _b64(requested_public_key),
        },
    )
    request_id = cast(str, created.json()["request_id"])
    missing_csrf = client.post(
        f"/auth/pairing/requests/{request_id}/reject",
        headers={"Origin": APP_ORIGIN},
    )
    assert missing_csrf.status_code == 403
    rejected = client.post(
        f"/auth/pairing/requests/{request_id}/reject",
        headers={
            "Origin": APP_ORIGIN,
            "X-CSRF-Token": cast(str, registered["csrf_token"]),
        },
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    assert client.get("/auth/pairing/requests").json() == {"requests": []}
