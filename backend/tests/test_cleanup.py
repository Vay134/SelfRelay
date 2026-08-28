from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from fastapi import WebSocket

from app.presence import (
    PRESENCE_HEARTBEAT_TIMEOUT,
    SIGNALING_STATE_RETENTION,
    WEBSOCKET_CLOSE_HEARTBEAT_TIMEOUT,
    ActiveConnection,
    PresenceManager,
)
from app.repositories.models import DeviceRecord
from app.repositories.transfers import InMemoryTransferRequestRepository
from app.transfers import TransferError, TransferService

START = datetime(2026, 1, 1, tzinfo=UTC)


class RecordingSocket:
    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []
        self.closed: list[int] = []

    async def send_json(self, payload: dict[str, object]) -> None:
        self.messages.append(payload)

    async def close(self, code: int = 1000) -> None:
        self.closed.append(code)


def _device(account_id: UUID, device_id: UUID) -> DeviceRecord:
    return DeviceRecord(
        id=device_id,
        user_id=account_id,
        epoch=0,
        label=str(device_id),
        signing_public_key_spki=b"spki",
        fingerprint=b"f" * 32,
        status="active",
        created_at=START,
        last_seen_at=START,
        revoked_at=None,
        approved_by_device_id=None,
    )


class Devices:
    def __init__(self, records: list[DeviceRecord]) -> None:
        self.records = {record.id: record for record in records}

    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None:
        record = self.records.get(device_id)
        return record if record is not None and record.user_id == account_id else None


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now = self.now + delta


def _connection(account_id: UUID, device_id: UUID, websocket: object) -> ActiveConnection:
    return ActiveConnection(
        id=uuid4(),
        account_id=account_id,
        device_id=device_id,
        session_id=uuid4(),
        websocket=cast(WebSocket, websocket),
        connected_at=START,
        last_heartbeat_at=START,
    )


def _service(clock: Clock) -> tuple[TransferService, PresenceManager, UUID, UUID, UUID]:
    account_id, sender_id, recipient_id = uuid4(), uuid4(), uuid4()
    devices = Devices([_device(account_id, sender_id), _device(account_id, recipient_id)])
    repository = InMemoryTransferRequestRepository(devices, clock=clock)
    manager = PresenceManager(devices, transfer_repository=repository, clock=clock)
    service = TransferService(repository, manager, devices, clock=clock)
    return service, manager, account_id, sender_id, recipient_id


def test_inactive_sockets_are_closed_and_released_after_the_heartbeat_timeout() -> None:
    async def exercise() -> None:
        clock = Clock()
        manager = PresenceManager(clock=clock)
        account_id, device_id = uuid4(), uuid4()
        socket = RecordingSocket()
        await manager.register(_connection(account_id, device_id, socket))

        clock.advance(PRESENCE_HEARTBEAT_TIMEOUT + timedelta(seconds=1))
        await manager.prune_expired(account_id)

        assert manager.active_socket_count() == 0
        assert socket.closed == [WEBSOCKET_CLOSE_HEARTBEAT_TIMEOUT]
        assert manager.metrics.value("socket_heartbeat_timeout") == 1

    asyncio.run(exercise())


def test_stale_signaling_state_is_released_after_its_retention_window() -> None:
    async def exercise() -> None:
        clock = Clock()
        manager = PresenceManager(clock=clock)
        connection = _connection(uuid4(), uuid4(), RecordingSocket())
        transfer_id = uuid4()
        assert await manager._record_signaling_use(transfer_id, connection, "sdp_offer")

        clock.advance(SIGNALING_STATE_RETENTION + timedelta(seconds=1))
        released = await manager.cleanup()

        assert released == {"signaling_state": 1}
        assert manager._signaling == {}
        assert manager._signaling_account_totals == {}

    asyncio.run(exercise())


@pytest.mark.parametrize("terminal", ["reject", "cancel", "expire"])
def test_terminal_transitions_release_signaling_state(terminal: str) -> None:
    async def exercise() -> None:
        clock = Clock()
        service, manager, account_id, sender_id, recipient_id = _service(clock)
        offer = await service.create_offer(account_id, sender_id, recipient_id)
        connection = _connection(account_id, sender_id, RecordingSocket())
        assert await manager._record_signaling_use(offer.id, connection, "sdp_offer")

        if terminal == "reject":
            await service.reject(account_id, offer.id, recipient_id)
        elif terminal == "cancel":
            await service.cancel(account_id, offer.id, sender_id)
        else:
            clock.advance(timedelta(hours=1))
            await service.expire(account_id, offer.id)

        assert manager._signaling == {}
        assert manager._signaling_account_totals == {}

    asyncio.run(exercise())


@pytest.mark.parametrize("terminal", ["reject", "cancel", "expire"])
def test_a_terminal_transfer_cannot_return_to_an_active_state(terminal: str) -> None:
    async def exercise() -> None:
        clock = Clock()
        service, _, account_id, sender_id, recipient_id = _service(clock)
        offer = await service.create_offer(account_id, sender_id, recipient_id)

        if terminal == "reject":
            final = await service.reject(account_id, offer.id, recipient_id)
        elif terminal == "cancel":
            final = await service.cancel(account_id, offer.id, sender_id)
        else:
            clock.advance(timedelta(hours=1))
            final = await service.expire(account_id, offer.id)

        for reactivate in (
            service.accept(account_id, offer.id, recipient_id),
            service.cancel(account_id, offer.id, sender_id),
            service.expire(account_id, offer.id),
        ):
            with pytest.raises(TransferError):
                await reactivate

        assert (await service.get(account_id, offer.id)).status == final.status

    asyncio.run(exercise())


def test_closing_a_socket_drops_its_queued_payloads() -> None:
    async def exercise() -> None:
        clock = Clock()
        manager = PresenceManager(clock=clock)
        account_id, device_id = uuid4(), uuid4()
        connection = _connection(account_id, device_id, RecordingSocket())
        await manager.register(connection)
        assert await manager.send_to_device(account_id, device_id, {"type": "presence"})

        await manager.close_all()

        assert manager._outbound == {}
        assert manager._signaling == {}
        assert manager.active_socket_count() == 0

    asyncio.run(exercise())
