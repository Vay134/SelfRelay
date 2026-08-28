from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

import pytest
from fastapi import WebSocket

from app.presence import (
    MAX_CONNECTIONS_PER_ACCOUNT,
    MAX_SIGNALING_MESSAGES,
    MAX_SIGNALING_MESSAGES_PER_ACCOUNT,
    MAX_SOCKET_MESSAGES,
    MAX_TOTAL_CONNECTIONS,
    MAX_WEBSOCKET_QUEUE_BYTES,
    MAX_WEBSOCKET_QUEUE_MESSAGES,
    WEBSOCKET_CLOSE_POLICY,
    WEBSOCKET_CLOSE_TRY_AGAIN,
    ActiveConnection,
    ConnectionLimitError,
    PresenceManager,
    _serve_connection,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


class BlockedSocket:
    """A socket whose writes never complete until the test releases them."""

    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []
        self.closed: list[int] = []
        self.release = asyncio.Event()

    async def send_json(self, payload: dict[str, object]) -> None:
        await self.release.wait()
        self.messages.append(payload)

    async def close(self, code: int = 1000) -> None:
        self.closed.append(code)


class QuietSocket:
    def __init__(self) -> None:
        self.closed: list[int] = []

    async def send_json(self, payload: dict[str, object]) -> None:
        return None

    async def close(self, code: int = 1000) -> None:
        self.closed.append(code)


class ChattySocket:
    """A socket that replays one message forever to exercise the inbound budget."""

    def __init__(self, message: str) -> None:
        self.message = message
        self.sent = 0
        self.closed: list[int] = []

    async def receive_text(self) -> str:
        return self.message

    async def send_json(self, payload: dict[str, object]) -> None:
        self.sent += 1

    async def close(self, code: int = 1000) -> None:
        self.closed.append(code)


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


def _manager() -> PresenceManager:
    return PresenceManager(clock=lambda: NOW)


def test_account_and_process_socket_limits_reject_further_connections() -> None:
    async def exercise() -> None:
        manager = _manager()
        account_id = uuid4()
        for _ in range(MAX_CONNECTIONS_PER_ACCOUNT):
            await manager.register(_connection(account_id, uuid4(), QuietSocket()))

        with pytest.raises(ConnectionLimitError):
            await manager.register(_connection(account_id, uuid4(), QuietSocket()))

        assert manager.active_socket_count() == MAX_CONNECTIONS_PER_ACCOUNT
        assert manager.metrics.value("socket_connection_rejected") == 1
        await manager.close_all()

    asyncio.run(exercise())


def test_process_wide_socket_limit_bounds_total_connections() -> None:
    async def exercise() -> None:
        manager = _manager()
        while manager.active_socket_count() < MAX_TOTAL_CONNECTIONS:
            account_id = uuid4()
            for _ in range(MAX_CONNECTIONS_PER_ACCOUNT):
                await manager.register(_connection(account_id, uuid4(), QuietSocket()))

        assert manager.active_socket_count() == MAX_TOTAL_CONNECTIONS
        with pytest.raises(ConnectionLimitError):
            await manager.register(_connection(uuid4(), uuid4(), QuietSocket()))

        assert manager.active_socket_count() == MAX_TOTAL_CONNECTIONS
        await manager.close_all()

    asyncio.run(exercise())


def test_one_socket_per_device_replaces_rather_than_accumulates() -> None:
    async def exercise() -> None:
        manager = _manager()
        account_id = uuid4()
        device_id = uuid4()
        first = _connection(account_id, device_id, QuietSocket())
        await manager.register(first)

        replaced = await manager.register(_connection(account_id, device_id, QuietSocket()))

        assert replaced is not None and replaced.id == first.id
        assert manager.active_socket_count() == 1
        await manager.close_all()

    asyncio.run(exercise())


def test_queued_message_overflow_closes_the_socket_instead_of_growing() -> None:
    async def exercise() -> None:
        manager = _manager()
        account_id, device_id = uuid4(), uuid4()
        socket = BlockedSocket()
        await manager.register(_connection(account_id, device_id, socket))

        accepted = 0
        for index in range(MAX_WEBSOCKET_QUEUE_MESSAGES * 2):
            if not await manager.send_to_device(account_id, device_id, {"n": index}):
                break
            accepted += 1

        assert accepted <= MAX_WEBSOCKET_QUEUE_MESSAGES + 1
        assert manager.metrics.value("socket_queue_rejected") == 1
        assert await manager.connection_for(account_id, device_id) is None
        assert socket.closed == [WEBSOCKET_CLOSE_TRY_AGAIN]
        await manager.close_all()

    asyncio.run(exercise())


def test_queued_byte_overflow_rejects_before_the_message_count_limit() -> None:
    async def exercise() -> None:
        manager = _manager()
        account_id, device_id = uuid4(), uuid4()
        socket = BlockedSocket()
        await manager.register(_connection(account_id, device_id, socket))
        payload: dict[str, object] = {"blob": "a" * (MAX_WEBSOCKET_QUEUE_BYTES // 8)}

        accepted = 0
        for _ in range(MAX_WEBSOCKET_QUEUE_MESSAGES):
            if not await manager.send_to_device(account_id, device_id, payload):
                break
            accepted += 1

        assert 0 < accepted < MAX_WEBSOCKET_QUEUE_MESSAGES
        assert manager.metrics.value("socket_queue_rejected") == 1
        assert socket.closed == [WEBSOCKET_CLOSE_TRY_AGAIN]
        await manager.close_all()

    asyncio.run(exercise())


def test_signaling_budgets_bound_each_transfer_and_the_whole_account() -> None:
    async def exercise() -> None:
        manager = _manager()
        account_id, device_id = uuid4(), uuid4()
        connection = _connection(account_id, device_id, QuietSocket())
        transfer_id = uuid4()

        charged = 0
        while await manager._record_signaling_use(transfer_id, connection, "ice_candidate"):
            charged += 1
        assert charged <= MAX_SIGNALING_MESSAGES

        while await manager._record_signaling_use(uuid4(), connection, "ice_candidate"):
            charged += 1
        assert charged == MAX_SIGNALING_MESSAGES_PER_ACCOUNT

    asyncio.run(exercise())


def test_released_signaling_state_returns_the_account_budget() -> None:
    async def exercise() -> None:
        manager = _manager()
        account_id, device_id = uuid4(), uuid4()
        connection = _connection(account_id, device_id, QuietSocket())
        transfer_id = uuid4()
        assert await manager._record_signaling_use(transfer_id, connection, "sdp_offer")

        await manager._clear_signaling_state(transfer_id)

        assert manager._signaling == {}
        assert manager._signaling_account_totals == {}
        assert manager.metrics.value("signaling_state_cleaned") == 1

    asyncio.run(exercise())


def test_socket_message_budget_closes_a_flooding_connection() -> None:
    async def exercise() -> None:
        manager = _manager()
        socket = ChattySocket('{"type": "ping"}')
        connection = _connection(uuid4(), uuid4(), socket)
        await manager.register(connection)

        await _serve_connection(cast(WebSocket, socket), connection, manager)

        assert socket.sent == MAX_SOCKET_MESSAGES
        assert socket.closed == [WEBSOCKET_CLOSE_POLICY]
        assert manager.metrics.value("socket_message_budget_exhausted") == 1
        await manager.close_all()

    asyncio.run(exercise())
