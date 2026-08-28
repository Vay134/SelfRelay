from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from fastapi import WebSocket

from app.presence import ActiveConnection, PresenceManager
from app.repositories.models import DeviceRecord
from app.repositories.transfers import InMemoryTransferRequestRepository
from app.transfers import TransferService


class FakeSocket:
    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []

    async def send_json(self, payload: dict[str, object]) -> None:
        self.messages.append(payload)


def _device(account_id: UUID, device_id: UUID) -> DeviceRecord:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return DeviceRecord(
        id=device_id,
        user_id=account_id,
        epoch=0,
        label=str(device_id),
        signing_public_key_spki=b"spki",
        fingerprint=b"f" * 32,
        status="active",
        created_at=now,
        last_seen_at=now,
        revoked_at=None,
        approved_by_device_id=None,
    )


class Devices:
    def __init__(self, records: list[DeviceRecord]) -> None:
        self.records = {record.id: record for record in records}

    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None:
        record = self.records.get(device_id)
        return record if record is not None and record.user_id == account_id else None


def _connection(
    account_id: UUID,
    device_id: UUID,
    websocket: FakeSocket,
    now: datetime,
) -> ActiveConnection:
    return ActiveConnection(
        id=uuid4(),
        account_id=account_id,
        device_id=device_id,
        session_id=uuid4(),
        websocket=cast(WebSocket, websocket),
        connected_at=now,
        last_heartbeat_at=now,
    )


def test_offer_accept_reject_and_cancel_notify_only_selected_participants() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        sender_id = uuid4()
        recipient_id = uuid4()
        devices = Devices([_device(account_id, sender_id), _device(account_id, recipient_id)])
        now = datetime(2026, 1, 1, tzinfo=UTC)
        repository = InMemoryTransferRequestRepository(devices, clock=lambda: now)
        sender_socket = FakeSocket()
        recipient_socket = FakeSocket()
        manager = PresenceManager(
            devices,
            transfer_repository=repository,
            clock=lambda: now,
        )
        await manager.register(_connection(account_id, sender_id, sender_socket, now))
        await manager.register(_connection(account_id, recipient_id, recipient_socket, now))
        service = TransferService(
            repository,
            manager,
            devices,
            clock=lambda: now,
        )

        offered = await service.create_offer(account_id, sender_id, recipient_id)
        assert offered.status == "offered"
        assert recipient_socket.messages[-1]["type"] == "transfer_offer"
        accepted = await service.accept(account_id, offered.id, recipient_id)
        assert accepted.status == "accepted"
        assert sender_socket.messages[-1]["type"] == "transfer_accepted"
        cancelled = await service.cancel(account_id, offered.id, sender_id)
        assert cancelled.status == "cancelled"
        assert sender_socket.messages[-1]["type"] == "transfer_cancelled"
        assert recipient_socket.messages[-1]["type"] == "transfer_cancelled"

    asyncio.run(exercise())


def test_signaling_transitions_and_forwards_typed_messages_between_selected_devices() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        sender_id = uuid4()
        recipient_id = uuid4()
        devices = Devices([_device(account_id, sender_id), _device(account_id, recipient_id)])
        now = datetime(2026, 1, 1, tzinfo=UTC)
        repository = InMemoryTransferRequestRepository(devices, clock=lambda: now)
        sender_socket = FakeSocket()
        recipient_socket = FakeSocket()
        sender = _connection(account_id, sender_id, sender_socket, now)
        recipient = _connection(account_id, recipient_id, recipient_socket, now)
        manager = PresenceManager(
            devices,
            transfer_repository=repository,
            clock=lambda: now,
        )
        await manager.register(sender)
        await manager.register(recipient)
        service = TransferService(repository, manager, devices, clock=lambda: now)
        transfer = await service.create_offer(account_id, sender_id, recipient_id)
        await service.accept(account_id, transfer.id, recipient_id)
        expires_at = int(transfer.expires_at.timestamp() * 1000)
        offer = {
            "type": "sdp_offer",
            "v": 1,
            "transfer_id": str(transfer.id),
            "sender_device_id": str(sender_id),
            "recipient_device_id": str(recipient_id),
            "expires_at": expires_at,
            "sdp": "v=0",
        }
        assert await manager.forward_signaling(sender, offer)
        assert (await repository.get_by_id(account_id, transfer.id)).status == "negotiating"  # type: ignore[union-attr]
        assert recipient_socket.messages[-1] == offer

        answer = {**offer, "type": "sdp_answer", "sdp": "v=0\r\na=answer"}
        assert await manager.forward_signaling(recipient, answer)
        assert sender_socket.messages[-1] == answer
        candidate = {key: value for key, value in offer.items() if key != "sdp"}
        candidate.update({"type": "ice_candidate", "candidate": "candidate:1"})
        assert await manager.forward_signaling(sender, candidate)
        assert recipient_socket.messages[-1] == candidate

        foreign_sender = _connection(uuid4(), sender_id, FakeSocket(), now)
        assert not await manager.forward_signaling(foreign_sender, offer)

    asyncio.run(exercise())


def test_stale_offer_expires_and_oversized_sdp_is_rejected() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        sender_id = uuid4()
        recipient_id = uuid4()
        devices = Devices([_device(account_id, sender_id), _device(account_id, recipient_id)])
        created_at = datetime(2026, 1, 1, tzinfo=UTC)
        now = created_at
        repository = InMemoryTransferRequestRepository(devices, clock=lambda: now)
        transfer = await repository.create(
            account_id,
            sender_id,
            recipient_id,
            1,
            created_at - timedelta(seconds=1),
        )
        manager = PresenceManager(devices, transfer_repository=repository, clock=lambda: now)
        sender_socket = FakeSocket()
        recipient_socket = FakeSocket()
        sender = _connection(account_id, sender_id, sender_socket, now)
        recipient = _connection(account_id, recipient_id, recipient_socket, now)
        await manager.register(sender)
        await manager.register(recipient)
        service = TransferService(repository, manager, devices, clock=lambda: now)
        with_expiry = await service.get(account_id, transfer.id)
        assert with_expiry.status == "expired"
        assert recipient_socket.messages[-1]["type"] == "transfer_expired"

        active = await repository.create(
            account_id,
            sender_id,
            recipient_id,
            1,
            now + timedelta(minutes=1),
        )
        await repository.accept(account_id, active.id, recipient_id)
        expires_at = int(active.expires_at.timestamp() * 1000)
        oversized = {
            "type": "sdp_offer",
            "v": 1,
            "transfer_id": str(active.id),
            "sender_device_id": str(sender_id),
            "recipient_device_id": str(recipient_id),
            "expires_at": expires_at,
            "sdp": "x" * 13_000,
        }
        assert not await manager.forward_signaling(sender, oversized)

    asyncio.run(exercise())
