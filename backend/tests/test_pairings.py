from __future__ import annotations

import base64
import hashlib
from collections.abc import Generator
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
from app.device_crypto import fingerprint_public_key, signed_message
from app.sessions import SESSION_COOKIE_NAME

APP_ORIGIN = 'http://localhost:5173'


def _environment() -> dict[str, str]:
    return {
        'APP_ENV': 'test',
        'APP_ORIGIN': APP_ORIGIN,
        'API_ORIGIN': 'http://localhost:8000',
        'DATABASE_URL': 'postgresql://localhost:5432/test',
        'LOG_LEVEL': 'INFO',
        'AUTH_ADAPTER': 'fake',
        'TURN_ADAPTER': 'fake',
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
    monkeypatch.setattr(main, 'load_settings', lambda: settings)
    monkeypatch.setattr(main, 'Database', FakeDatabase)
    with TestClient(main.app, base_url='https://localhost:8000') as test_client:
        yield test_client


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def _new_key() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key


def _sign(private_key: ec.EllipticCurvePrivateKey, payload: dict[str, object]) -> str:
    der_signature = private_key.sign(signed_message(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return _b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))


def _bootstrap(client: TestClient) -> dict[str, object]:
    email = 'alice@example.test'
    started = client.post('/auth/otp/start', json={'email': email})
    assert started.status_code == 202
    gateway = main.app.state.auth_gateway
    assert isinstance(gateway, FakeAuthGateway)
    verified = client.post(
        '/auth/otp/verify',
        json={'email': email, 'otp': gateway.otp_for(email)},
    )
    assert verified.status_code == 200
    return cast(dict[str, object], verified.json())


def _register(
    client: TestClient,
    private_key: ec.EllipticCurvePrivateKey,
    public_key: bytes,
) -> dict[str, object]:
    bootstrap = _bootstrap(client)
    challenge = client.post(
        '/auth/devices/registration-challenge',
        headers={'Origin': APP_ORIGIN},
        json={
            'bootstrap_token': bootstrap['bootstrap_token'],
            'public_key': _b64(public_key),
            'label': 'Primary browser',
        },
    )
    assert challenge.status_code == 200
    body = cast(dict[str, object], challenge.json())
    completed = client.post(
        '/auth/devices/registration',
        headers={'Origin': APP_ORIGIN},
        json={
            'challenge_id': body['challenge_id'],
            'signature': _sign(private_key, cast(dict[str, object], body['payload'])),
        },
    )
    assert completed.status_code == 200
    return cast(dict[str, object], completed.json())


def test_linking_code_is_hashed_one_time_and_binds_the_new_key(client: TestClient) -> None:
    issuer_key, issuer_public_key = _new_key()
    first = _register(client, issuer_key, issuer_public_key)
    issuer = cast(dict[str, object], first['device'])
    csrf_token = cast(str, first['csrf_token'])

    missing_csrf = client.post('/auth/devices/linking-otp', headers={'Origin': APP_ORIGIN})
    assert missing_csrf.status_code == 403

    created = client.post(
        '/auth/devices/linking-otp',
        headers={'Origin': APP_ORIGIN, 'X-CSRF-Token': csrf_token},
    )
    assert created.status_code == 200
    code_body = cast(dict[str, object], created.json())
    code = cast(str, code_body['otp'])
    assert len(code) == 6
    record = next(iter(main.app.state.device_linking_otp_repository._records.values()))
    assert record.otp_hash == hashlib.sha256(code.encode('ascii')).digest()
    assert code not in repr(record)

    client.cookies.clear()
    new_key, new_public_key = _new_key()
    challenge = client.post(
        '/auth/devices/linking-challenge',
        headers={'Origin': APP_ORIGIN},
        json={
            'otp': code,
            'public_key': _b64(new_public_key),
            'label': 'Linked browser',
        },
    )
    assert challenge.status_code == 200
    challenge_body = cast(dict[str, object], challenge.json())
    completed = client.post(
        '/auth/devices/linking',
        headers={'Origin': APP_ORIGIN},
        json={
            'challenge_id': challenge_body['challenge_id'],
            'signature': _sign(new_key, cast(dict[str, object], challenge_body['payload'])),
        },
    )
    assert completed.status_code == 200
    result = cast(dict[str, object], completed.json())
    assert result['fallback'] is False
    linked = cast(dict[str, object], result['device'])
    assert linked['linked_by_device_id'] == issuer['device_id']
    assert 'signing_public_key_spki' not in linked
    assert _b64(new_public_key) not in completed.text
    assert client.cookies.get(SESSION_COOKIE_NAME)

    replay = client.post(
        '/auth/devices/linking-challenge',
        headers={'Origin': APP_ORIGIN},
        json={
            'otp': code,
            'public_key': _b64(new_public_key),
            'label': 'Replay',
        },
    )
    assert replay.status_code == 401

    devices = client.get('/auth/devices', headers={'Origin': APP_ORIGIN})
    assert devices.status_code == 200
    assert len(devices.json()['devices']) == 2


def test_linking_code_cannot_be_redeemed_after_issuer_logs_out(client: TestClient) -> None:
    issuer_key, issuer_public_key = _new_key()
    first = _register(client, issuer_key, issuer_public_key)
    created = client.post(
        '/auth/devices/linking-otp',
        headers={
            'Origin': APP_ORIGIN,
            'X-CSRF-Token': cast(str, first['csrf_token']),
        },
    )
    assert created.status_code == 200
    code = cast(str, created.json()['otp'])

    logged_out = client.post(
        '/auth/logout',
        headers={
            'Origin': APP_ORIGIN,
            'X-CSRF-Token': cast(str, first['csrf_token']),
        },
    )
    assert logged_out.status_code == 200
    client.cookies.clear()

    _, new_public_key = _new_key()
    challenge = client.post(
        '/auth/devices/linking-challenge',
        headers={'Origin': APP_ORIGIN},
        json={'otp': code, 'public_key': _b64(new_public_key), 'label': 'Blocked browser'},
    )
    assert challenge.status_code == 401
    assert fingerprint_public_key(issuer_public_key)
