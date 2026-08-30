"""Deterministic flooding harness proving bounded state and predictable rejection."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from fastapi import WebSocket

from app.presence import (
    MAX_CONNECTIONS_PER_ACCOUNT,
    MAX_SIGNALING_ICE_CANDIDATES,
    MAX_SIGNALING_MESSAGES,
    MAX_SIGNALING_MESSAGES_PER_ACCOUNT,
    MAX_TOTAL_CONNECTIONS,
    MAX_WEBSOCKET_QUEUE_BYTES,
    MAX_WEBSOCKET_QUEUE_MESSAGES,
    ActiveConnection,
    ConnectionLimitError,
    PresenceManager,
)
from app.repositories.models import DeviceRecord
from app.repositories.transfers import InMemoryTransferRequestRepository
from app.transfers import (
    MAX_ACTIVE_TRANSFERS_PER_ACCOUNT,
    TransferCapacityError,
    TransferService,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
FLOOD = 4_096


class BlockedSocket:
    def __init__(self) -> None:
        self.closed: list[int] = []
        self.release = asyncio.Event()

    async def send_json(self, payload: dict[str, object]) -> None:
        await self.release.wait()

    async def close(self, code: int = 1000) -> None:
        self.closed.append(code)


class QuietSocket:
    async def send_json(self, payload: dict[str, object]) -> None:
        return None

    async def close(self, code: int = 1000) -> None:
        return None


def _device(account_id: UUID, device_id: UUID) -> DeviceRecord:
    return DeviceRecord(
        id=device_id,
        user_id=account_id,
        epoch=0,
        label=str(device_id),
        signing_public_key_spki=b"spki",
        fingerprint=b"f" * 32,
        status="active",
        created_at=NOW,
        last_seen_at=NOW,
        revoked_at=None,
        linked_by_device_id=None,
    )


class Devices:
    def __init__(self, records: list[DeviceRecord]) -> None:
        self.records = {record.id: record for record in records}

    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None:
        record = self.records.get(device_id)
        return record if record is not None and record.user_id == account_id else None


def _connection(account_id: UUID, device_id: UUID, websocket: object) -> ActiveConnection:
    return ActiveConnection(
        id=uuid4(),
        account_id=account_id,
        device_id=device_id,
        session_id=uuid4(),
        websocket=cast(WebSocket, websocket),
        connected_at=NOW,
        last_heartbeat_at=NOW,
    )


def test_a_socket_flood_is_rejected_without_unbounded_growth() -> None:
    async def exercise() -> None:
        manager = PresenceManager(clock=lambda: NOW)
        rejected = 0

        for _ in range(FLOOD):
            account_id = uuid4()
            for _ in range(MAX_CONNECTIONS_PER_ACCOUNT + 2):
                try:
                    await manager.register(_connection(account_id, uuid4(), QuietSocket()))
                except ConnectionLimitError:
                    rejected += 1
            if manager.active_socket_count() >= MAX_TOTAL_CONNECTIONS:
                break

        assert rejected > 0
        assert manager.active_socket_count() <= MAX_TOTAL_CONNECTIONS
        assert len(manager._outbound) <= MAX_TOTAL_CONNECTIONS
        assert manager.metrics.value("socket_connection_rejected") == rejected
        await manager.close_all()
        assert manager.active_socket_count() == 0
        assert manager._outbound == {}

    asyncio.run(exercise())


def test_an_outbound_flood_stays_within_the_queue_and_byte_budget() -> None:
    async def exercise() -> None:
        manager = PresenceManager(clock=lambda: NOW)
        account_id, device_id = uuid4(), uuid4()
        socket = BlockedSocket()
        await manager.register(_connection(account_id, device_id, socket))
        accepted = 0

        for index in range(FLOOD):
            if not await manager.send_to_device(account_id, device_id, {"n": index}):
                break
            accepted += 1

        assert accepted <= MAX_WEBSOCKET_QUEUE_MESSAGES + 1
        assert socket.closed  # the flooded socket is closed, not buffered forever
        snapshot = await manager.resource_snapshot()
        assert snapshot["queued_messages"] == 0
        assert snapshot["queued_bytes"] <= MAX_WEBSOCKET_QUEUE_BYTES
        await manager.close_all()

    asyncio.run(exercise())


def test_a_candidate_flood_is_capped_per_transfer_and_per_account() -> None:
    async def exercise() -> None:
        manager = PresenceManager(clock=lambda: NOW)
        account_id, device_id = uuid4(), uuid4()
        connection = _connection(account_id, device_id, QuietSocket())
        transfer_id = uuid4()
        charged = 0

        for _ in range(FLOOD):
            if not await manager._record_signaling_use(transfer_id, connection, "ice_candidate"):
                break
            charged += 1

        assert charged == MAX_SIGNALING_ICE_CANDIDATES
        assert manager._signaling[transfer_id].total <= MAX_SIGNALING_MESSAGES
        assert len(manager._signaling) == 1

        for _ in range(FLOOD):
            if not await manager._record_signaling_use(uuid4(), connection, "ice_candidate"):
                break

        assert manager._signaling_account_totals[account_id] == MAX_SIGNALING_MESSAGES_PER_ACCOUNT

    asyncio.run(exercise())


def test_an_offer_flood_is_capped_per_account() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        device_ids = [uuid4() for _ in range(MAX_ACTIVE_TRANSFERS_PER_ACCOUNT * 2)]
        devices = Devices([_device(account_id, device_id) for device_id in device_ids])
        repository = InMemoryTransferRequestRepository(devices, clock=lambda: NOW)
        service = TransferService(repository, None, devices, clock=lambda: NOW)
        created = 0
        rejected = 0

        for index in range(FLOOD):
            sender_id = device_ids[index % len(device_ids)]
            recipient_id = device_ids[(index + 1) % len(device_ids)]
            try:
                await service.create_offer(account_id, sender_id, recipient_id)
            except TransferCapacityError:
                rejected += 1
                if rejected > MAX_ACTIVE_TRANSFERS_PER_ACCOUNT:
                    break
            else:
                created += 1

        assert created == MAX_ACTIVE_TRANSFERS_PER_ACCOUNT
        assert rejected > 0
        assert len(await repository.list_for_account(account_id)) == created

    asyncio.run(exercise())
