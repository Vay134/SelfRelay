from __future__ import annotations

import asyncio
import base64
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import main
from app.adapters import FakeAuthGateway
from app.config import load_settings
from app.device_crypto import signed_message
from app.presence import (
    MAX_WEBSOCKET_MESSAGE_BYTES,
    WEBSOCKET_CLOSE_MESSAGE_TOO_LARGE,
    ActiveConnection,
    DeviceRepositoryPort,
    PresenceManager,
    WebSocketTicketService,
)
from app.repositories.models import DeviceRecord
from app.repositories.websocket_tickets import InMemoryWebSocketTicketRepository
from app.sessions import InMemorySessionRepository, SessionService

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


def _register(
    client: TestClient,
    email: str,
) -> dict[str, object]:
    private_key, public_key = _new_key()
    started = client.post("/auth/otp/start", json={"email": email})
    assert started.status_code == 202
    gateway = main.app.state.auth_gateway
    assert isinstance(gateway, FakeAuthGateway)
    verified = client.post(
        "/auth/otp/verify",
        json={"email": email, "otp": gateway.otp_for(email)},
    )
    bootstrap = cast(dict[str, object], verified.json())
    challenge = client.post(
        "/auth/devices/registration-challenge",
        headers={"Origin": APP_ORIGIN},
        json={
            "bootstrap_token": bootstrap["bootstrap_token"],
            "public_key": _b64(public_key),
            "label": "Laptop",
        },
    )
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


def _prepare_second_browser(
    client: TestClient,
    registered: dict[str, object],
) -> tuple[str, str, UUID, UUID]:
    account_id = UUID(cast(str, registered["account_id"]))
    first_device = cast(dict[str, object], registered["device"])
    first_session = cast(dict[str, object], registered["session"])
    first_device_id = UUID(cast(str, first_device["device_id"]))
    first_session_id = UUID(cast(str, first_session["session_id"]))

    async def prepare() -> tuple[str, str, UUID, UUID]:
        session_repository = main.app.state.session_repository
        session = await session_repository.find_current_by_id(first_session_id)
        assert session is not None
        second_device = await main.app.state.device_repository.create(
            account_id,
            session.epoch,
            "Phone",
            b"second-browser-spki",
            b"s" * 32,
        )
        second_session = await main.app.state.session_service.create(
            account_id,
            second_device.id,
            session.epoch,
        )
        ticket_service = cast(WebSocketTicketService, main.app.state.websocket_ticket_service)
        first_ticket, _ = await ticket_service.issue(session)
        second_ticket, _ = await ticket_service.issue(second_session.record)
        transfer = await main.app.state.transfer_service.create_offer(
            account_id,
            first_device_id,
            second_device.id,
        )
        accepted = await main.app.state.transfer_service.accept(
            account_id,
            transfer.id,
            second_device.id,
        )
        assert accepted.status == "accepted"
        return first_ticket, second_ticket, second_device.id, transfer.id

    assert client.portal is not None
    return client.portal.call(prepare)


def _issue_fresh_ticket(client: TestClient, session_id: UUID) -> str:
    async def issue() -> str:
        session = await main.app.state.session_repository.find_current_by_id(session_id)
        assert session is not None
        ticket_service = cast(WebSocketTicketService, main.app.state.websocket_ticket_service)
        ticket, _ = await ticket_service.issue(session)
        return ticket

    assert client.portal is not None
    return client.portal.call(issue)


def test_in_memory_ticket_is_single_use_and_session_bound() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        device_id = uuid4()
        sessions = InMemorySessionRepository()
        session = await SessionService(sessions).create(account_id, device_id, 0)
        repository = InMemoryWebSocketTicketRepository(sessions)
        from app.sessions import hash_secret, new_opaque_token

        raw_ticket = new_opaque_token()
        created = await repository.create(
            account_id,
            session.record.id,
            hash_secret(raw_ticket),
            datetime.now(UTC) + timedelta(minutes=1),
        )

        consumed = await repository.consume_for_socket(hash_secret(raw_ticket))
        replay = await repository.consume_for_socket(hash_secret(raw_ticket))

        assert consumed is not None
        assert consumed.id == created.id
        assert replay is None

    asyncio.run(exercise())


class FakeSocket:
    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []
        self.closed: list[int] = []

    async def send_json(self, payload: dict[str, object]) -> None:
        self.messages.append(payload)

    async def close(self, code: int = 1000) -> None:
        self.closed.append(code)


def _device(account_id: UUID, device_id: UUID, label: str) -> DeviceRecord:
    now = datetime.now(UTC)
    return DeviceRecord(
        id=device_id,
        user_id=account_id,
        epoch=0,
        label=label,
        signing_public_key_spki=b"spki",
        fingerprint=b"f" * 32,
        status="active",
        created_at=now,
        last_seen_at=now,
        revoked_at=None,
        approved_by_device_id=None,
    )


def test_presence_is_account_scoped_and_heartbeat_expiry_removes_socket() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        foreign_account_id = uuid4()
        first_device_id = uuid4()
        second_device_id = uuid4()
        devices = {
            first_device_id: _device(account_id, first_device_id, "Laptop"),
            second_device_id: _device(foreign_account_id, second_device_id, "Phone"),
        }

        class Devices:
            async def get_by_id(self, owner_id: UUID, device_id: UUID) -> DeviceRecord | None:
                device = devices.get(device_id)
                return device if device is not None and device.user_id == owner_id else None

        now = datetime(2026, 1, 1, tzinfo=UTC)
        manager = PresenceManager(
            cast(DeviceRepositoryPort, Devices()),
            clock=lambda: now,
            heartbeat_timeout=timedelta(seconds=5),
        )
        first_socket = FakeSocket()
        foreign_socket = FakeSocket()
        first = ActiveConnection(
            id=uuid4(),
            account_id=account_id,
            device_id=first_device_id,
            session_id=uuid4(),
            websocket=cast(WebSocket, first_socket),
            connected_at=now,
            last_heartbeat_at=now,
        )
        foreign = ActiveConnection(
            id=uuid4(),
            account_id=foreign_account_id,
            device_id=second_device_id,
            session_id=uuid4(),
            websocket=cast(WebSocket, foreign_socket),
            connected_at=now,
            last_heartbeat_at=now,
        )
        await manager.register(first)
        await manager.register(foreign)
        await manager.broadcast_presence(account_id)
        assert await manager.flush_outbound()

        assert first_socket.messages == [
            {
                "type": "presence",
                "devices": [{"device_id": str(first_device_id), "label": "Laptop"}],
            }
        ]
        assert foreign_socket.messages == []

        now = now + timedelta(seconds=6)
        await manager.prune_expired(account_id)
        assert await manager.online_devices(account_id) == []
        assert first_socket.closed == [4008]

    asyncio.run(exercise())


def test_ticket_route_requires_csrf_and_socket_origin_and_replay_is_rejected(
    client: TestClient,
) -> None:
    registered = _register(client, "presence@example.test")
    csrf_token = cast(str, registered["csrf_token"])
    issued = client.post(
        "/auth/websocket/ticket",
        headers={"Origin": APP_ORIGIN, "X-CSRF-Token": csrf_token},
    )
    assert issued.status_code == 200
    ticket = cast(str, issued.json()["ticket"])

    with client.websocket_connect(
        f"/auth/ws?ticket={ticket}",
        headers={"Origin": APP_ORIGIN},
    ) as websocket:
        assert websocket.receive_json()["devices"][0]["label"] == "Laptop"
        websocket.send_json({"type": "heartbeat"})
        assert websocket.receive_json() == {"type": "heartbeat"}

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            f"/auth/ws?ticket={ticket}",
            headers={"Origin": APP_ORIGIN},
        ):
            pass

    missing_csrf = client.post("/auth/websocket/ticket", headers={"Origin": APP_ORIGIN})
    assert missing_csrf.status_code == 403

    next_ticket_response = client.post(
        "/auth/websocket/ticket",
        headers={"Origin": APP_ORIGIN, "X-CSRF-Token": csrf_token},
    )
    next_ticket = cast(str, next_ticket_response.json()["ticket"])
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            f"/auth/ws?ticket={next_ticket}",
            headers={"Origin": "https://evil.example"},
        ):
            pass


def test_websocket_closes_oversized_messages_with_bounded_payload_code(
    client: TestClient,
) -> None:
    registered = _register(client, "presence-size@example.test")
    csrf_token = cast(str, registered["csrf_token"])
    issued = client.post(
        "/auth/websocket/ticket",
        headers={"Origin": APP_ORIGIN, "X-CSRF-Token": csrf_token},
    )
    assert issued.status_code == 200
    ticket = cast(str, issued.json()["ticket"])

    with client.websocket_connect(
        f"/auth/ws?ticket={ticket}",
        headers={"Origin": APP_ORIGIN},
    ) as websocket:
        websocket.receive_json()
        with pytest.raises(WebSocketDisconnect) as disconnect:
            websocket.send_text("x" * (MAX_WEBSOCKET_MESSAGE_BYTES + 1))
            websocket.receive_text()

    assert disconnect.value.code == WEBSOCKET_CLOSE_MESSAGE_TOO_LARGE


def test_two_browser_sessions_signal_and_reconnect_after_backend_restart(
    client: TestClient,
) -> None:
    registered = _register(client, "presence-integration@example.test")
    first_session = cast(dict[str, object], registered["session"])
    first_session_id = UUID(cast(str, first_session["session_id"]))
    first_device = cast(dict[str, object], registered["device"])
    first_device_id = UUID(cast(str, first_device["device_id"]))
    first_ticket, second_ticket, second_device_id, transfer_id = _prepare_second_browser(
        client,
        registered,
    )

    with client.websocket_connect(
        f"/auth/ws?ticket={first_ticket}",
        headers={"Origin": APP_ORIGIN},
    ) as first_browser:
        initial = first_browser.receive_json()
        assert initial["devices"] == [{"device_id": str(first_device_id), "label": "Laptop"}]

        with client.websocket_connect(
            f"/auth/ws?ticket={second_ticket}",
            headers={"Origin": APP_ORIGIN},
        ) as second_browser:
            expected_devices = [
                {"device_id": str(device_id), "label": label}
                for device_id, label in sorted(
                    ((first_device_id, "Laptop"), (second_device_id, "Phone")),
                    key=lambda item: str(item[0]),
                )
            ]
            assert second_browser.receive_json() == {
                "type": "presence",
                "devices": expected_devices,
            }
            assert first_browser.receive_json() == {
                "type": "presence",
                "devices": expected_devices,
            }

            expires_at = int((datetime.now(UTC) + timedelta(minutes=1)).timestamp() * 1000)
            offer = {
                "type": "sdp_offer",
                "v": 1,
                "transfer_id": str(transfer_id),
                "sender_device_id": str(first_device_id),
                "recipient_device_id": str(second_device_id),
                "expires_at": expires_at,
                "sdp": "v=0",
            }
            first_browser.send_json(offer)
            assert second_browser.receive_json() == offer

            answer = {**offer, "type": "sdp_answer", "sdp": "v=0\\r\\na=answer"}
            second_browser.send_json(answer)
            assert first_browser.receive_json() == answer

            manager = cast(PresenceManager, main.app.state.presence_manager)
            assert client.portal is not None
            client.portal.call(manager.close_all)
            with pytest.raises(WebSocketDisconnect) as first_disconnect:
                first_browser.receive_json()
            with pytest.raises(WebSocketDisconnect) as second_disconnect:
                second_browser.receive_json()
            assert first_disconnect.value.code == 1001
            assert second_disconnect.value.code == 1001

    reconnected_ticket = _issue_fresh_ticket(client, first_session_id)
    with client.websocket_connect(
        f"/auth/ws?ticket={reconnected_ticket}",
        headers={"Origin": APP_ORIGIN},
    ) as reconnected_browser:
        assert reconnected_browser.receive_json() == {
            "type": "presence",
            "devices": [
                {"device_id": str(first_device_id), "label": "Laptop"},
            ],
        }
