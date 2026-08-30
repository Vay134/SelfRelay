from __future__ import annotations

import base64
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from app import main
from app.adapters import FakeAuthGateway
from app.config import load_settings
from app.device_crypto import (
    canonical_public_key,
    fingerprint_public_key,
    signed_message,
    verify_p1363_signature,
)
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


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _new_key() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key


def _sign(private_key: ec.EllipticCurvePrivateKey, payload: dict[str, object]) -> str:
    der_signature = private_key.sign(signed_message(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _bootstrap(client: TestClient, email: str = "alice@example.test") -> dict[str, object]:
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
    private_key: ec.EllipticCurvePrivateKey,
    public_key: bytes,
    *,
    endpoint: str = "/auth/devices/registration-challenge",
) -> dict[str, object]:
    bootstrap = _bootstrap(client)
    challenge = client.post(
        endpoint,
        headers={"Origin": APP_ORIGIN},
        json={
            "bootstrap_token": cast(str, bootstrap["bootstrap_token"]),
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
            "challenge_id": cast(str, challenge_body["challenge_id"]),
            "signature": _sign(
                private_key,
                cast(dict[str, object], challenge_body["payload"]),
            ),
        },
    )
    assert completed.status_code == 200
    return cast(dict[str, object], completed.json())


def test_public_key_validation_and_p1363_signature_helpers() -> None:
    private_key, public_key = _new_key()
    message = b"device challenge"
    der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    assert canonical_public_key(public_key) == public_key
    assert len(fingerprint_public_key(public_key)) == 32
    assert verify_p1363_signature(public_key, signature, message)
    assert not verify_p1363_signature(public_key, signature[:-1] + b"0", message)


def test_first_registration_issues_cookie_and_lists_safe_device_metadata(
    client: TestClient,
) -> None:
    private_key, public_key = _new_key()
    result = _register(client, private_key, public_key)

    assert result["authenticated"] is True
    device = cast(dict[str, object], result["device"])
    assert device["fingerprint"] == _b64(fingerprint_public_key(public_key))
    assert "signing_public_key_spki" not in device
    assert client.cookies.get(SESSION_COOKIE_NAME)

    devices = client.get("/auth/devices", headers={"Origin": APP_ORIGIN})
    assert devices.status_code == 200
    assert len(devices.json()["devices"]) == 1
    assert _b64(public_key) not in devices.text


def test_returning_device_challenge_is_one_time_and_rejects_tampering(client: TestClient) -> None:
    private_key, public_key = _new_key()
    first = _register(client, private_key, public_key)
    account_id = cast(str, first["account_id"])
    device_id = cast(str, cast(dict[str, object], first["device"])["device_id"])
    old_cookie = client.cookies.get(SESSION_COOKIE_NAME)
    assert old_cookie

    challenge = client.post(
        "/auth/devices/login/challenge",
        headers={"Origin": APP_ORIGIN},
        json={"account_id": account_id, "device_id": device_id},
    )
    assert challenge.status_code == 200
    challenge_body = cast(dict[str, object], challenge.json())
    altered_payload = dict(cast(dict[str, object], challenge_body["payload"]))
    altered_payload["device_epoch"] = 999
    tampered = client.post(
        "/auth/devices/login",
        headers={"Origin": APP_ORIGIN},
        json={
            "account_id": account_id,
            "challenge_id": cast(str, challenge_body["challenge_id"]),
            "nonce": cast(str, challenge_body["nonce"]),
            "signature": _sign(private_key, altered_payload),
        },
    )
    assert tampered.status_code == 401

    renewed = client.post(
        "/auth/devices/login",
        headers={"Origin": APP_ORIGIN},
        json={
            "account_id": account_id,
            "challenge_id": cast(str, challenge_body["challenge_id"]),
            "nonce": cast(str, challenge_body["nonce"]),
            "signature": _sign(
                private_key,
                cast(dict[str, object], challenge_body["payload"]),
            ),
        },
    )
    assert renewed.status_code == 200
    assert renewed.json()["authenticated"] is True
    replay = client.post(
        "/auth/devices/login",
        headers={"Origin": APP_ORIGIN},
        json={
            "account_id": account_id,
            "challenge_id": cast(str, challenge_body["challenge_id"]),
            "nonce": cast(str, challenge_body["nonce"]),
            "signature": _sign(
                private_key,
                cast(dict[str, object], challenge_body["payload"]),
            ),
        },
    )
    assert replay.status_code == 401
    assert old_cookie != client.cookies.get(SESSION_COOKIE_NAME)


def test_email_fallback_adds_only_the_current_browser(client: TestClient) -> None:
    private_key, public_key = _new_key()
    first = _register(client, private_key, public_key)
    fallback_private_key, fallback_public_key = _new_key()
    bootstrap = _bootstrap(client)
    challenge = client.post(
        "/auth/devices/registration-challenge",
        headers={"Origin": APP_ORIGIN},
        json={
            "bootstrap_token": cast(str, bootstrap["bootstrap_token"]),
            "public_key": _b64(fallback_public_key),
            "label": "Fallback browser",
        },
    )
    assert challenge.status_code == 200
    challenge_body = cast(dict[str, object], challenge.json())
    completed = client.post(
        "/auth/devices/registration",
        headers={"Origin": APP_ORIGIN},
        json={
            "challenge_id": cast(str, challenge_body["challenge_id"]),
            "signature": _sign(
                fallback_private_key,
                cast(dict[str, object], challenge_body["payload"]),
            ),
        },
    )
    assert completed.status_code == 200
    result = completed.json()
    assert result["fallback"] is True
    assert "warning" not in result
    fallback_device = cast(dict[str, object], result["device"])
    first_device = cast(dict[str, object], first["device"])
    assert fallback_device["epoch"] == first_device["epoch"]

    devices = client.get("/auth/devices", headers={"Origin": APP_ORIGIN})
    assert devices.status_code == 200
    old = next(
        device
        for device in devices.json()["devices"]
        if device["device_id"] == first_device["device_id"]
    )
    assert old["status"] == "active"


def test_expired_returning_device_challenge_is_rejected(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key, public_key = _new_key()
    first = _register(client, private_key, public_key)
    account_id = cast(str, first["account_id"])
    first_device = cast(dict[str, object], first["device"])
    device_id = cast(str, first_device["device_id"])
    challenge = client.post(
        "/auth/devices/login/challenge",
        headers={"Origin": APP_ORIGIN},
        json={"account_id": account_id, "device_id": device_id},
    )
    assert challenge.status_code == 200
    challenge_body = cast(dict[str, object], challenge.json())
    service = main.app.state.device_auth_service
    monkeypatch.setattr(
        service,
        "_clock",
        lambda: datetime.now(UTC) + timedelta(minutes=6),
    )
    expired = client.post(
        "/auth/devices/login",
        headers={"Origin": APP_ORIGIN},
        json={
            "account_id": account_id,
            "challenge_id": cast(str, challenge_body["challenge_id"]),
            "nonce": cast(str, challenge_body["nonce"]),
            "signature": _sign(
                private_key,
                cast(dict[str, object], challenge_body["payload"]),
            ),
        },
    )
    assert expired.status_code == 401


def test_renaming_and_logging_out_device_blocks_existing_challenge(client: TestClient) -> None:
    private_key, public_key = _new_key()
    first = _register(client, private_key, public_key)
    account_id = cast(str, first["account_id"])
    first_device = cast(dict[str, object], first["device"])
    device_id = cast(str, first_device["device_id"])
    csrf_token = cast(str, first["csrf_token"])
    renamed = client.patch(
        f"/auth/devices/{device_id}",
        headers={"Origin": APP_ORIGIN, "X-CSRF-Token": csrf_token},
        json={"label": "Renamed browser"},
    )
    assert renamed.status_code == 200
    assert renamed.json()["device"]["label"] == "Renamed browser"

    challenge = client.post(
        "/auth/devices/login/challenge",
        headers={"Origin": APP_ORIGIN},
        json={"account_id": account_id, "device_id": device_id},
    )
    assert challenge.status_code == 200
    challenge_body = cast(dict[str, object], challenge.json())
    revoked = client.delete(
        f"/auth/devices/{device_id}",
        headers={"Origin": APP_ORIGIN, "X-CSRF-Token": csrf_token},
    )
    assert revoked.status_code == 200
    assert revoked.json()["logged_out"] is True
    assert revoked.json()["device"]["status"] == "inactive"
    blocked = client.post(
        "/auth/devices/login",
        headers={"Origin": APP_ORIGIN},
        json={
            "account_id": account_id,
            "challenge_id": cast(str, challenge_body["challenge_id"]),
            "nonce": cast(str, challenge_body["nonce"]),
            "signature": _sign(
                private_key,
                cast(dict[str, object], challenge_body["payload"]),
            ),
        },
    )
    assert blocked.status_code == 401
