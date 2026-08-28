"""WebSocket ticket admission and in-process account presence."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Annotated, Protocol, cast
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)

from .metrics import RuntimeMetrics
from .repositories.models import (
    DeviceRecord,
    SessionRecord,
    TransferRequestRecord,
    WebSocketTicketRecord,
)
from .security import check_optional_origin
from .session_api import get_authenticated_session, require_session_csrf
from .sessions import hash_secret, new_opaque_token

WEBSOCKET_TICKET_LIFETIME = timedelta(minutes=1)
PRESENCE_HEARTBEAT_TIMEOUT = timedelta(seconds=45)
MAX_WEBSOCKET_MESSAGE_BYTES = 16 * 1024
MAX_SIGNALING_SDP_BYTES = 12 * 1024
MAX_SIGNALING_ICE_CANDIDATE_BYTES = 2048
MAX_SIGNALING_HANDSHAKE_BYTES = 8 * 1024
MAX_SIGNALING_ICE_CANDIDATES = 64
MAX_SIGNALING_MESSAGES = 128
MAX_SIGNALING_MESSAGES_PER_ACCOUNT = 512
MAX_SOCKET_MESSAGES = 4096
MAX_WEBSOCKET_QUEUE_MESSAGES = 32
MAX_WEBSOCKET_QUEUE_BYTES = 256 * 1024
# Compatibility alias for socket-focused callers.
MAX_SOCKET_QUEUE_MESSAGES = MAX_WEBSOCKET_QUEUE_MESSAGES
MAX_CONNECTIONS_PER_ACCOUNT = 8
# One socket per device is structural: a newer socket replaces the older one.
MAX_CONNECTIONS_PER_DEVICE = 1
MAX_TOTAL_CONNECTIONS = 512
WEBSOCKET_SEND_TIMEOUT_SECONDS = 5.0
SIGNALING_STATE_RETENTION = timedelta(minutes=11)

# Descriptive aliases for callers that name limits by their payload type.
MAX_SDP_BYTES = MAX_SIGNALING_SDP_BYTES
MAX_ICE_CANDIDATE_BYTES = MAX_SIGNALING_ICE_CANDIDATE_BYTES
MAX_HANDSHAKE_BYTES = MAX_SIGNALING_HANDSHAKE_BYTES
MAX_ICE_CANDIDATES_PER_TRANSFER = MAX_SIGNALING_ICE_CANDIDATES

PRESENCE_EVENT_TYPE = "presence"
HEARTBEAT_MESSAGE_TYPE = "heartbeat"
PING_MESSAGE_TYPE = "ping"
PONG_MESSAGE_TYPE = "pong"

WEBSOCKET_CLOSE_POLICY = 1008
WEBSOCKET_CLOSE_UNSUPPORTED_DATA = 1003
WEBSOCKET_CLOSE_MESSAGE_TOO_LARGE = 1009
WEBSOCKET_CLOSE_HEARTBEAT_TIMEOUT = 4008
WEBSOCKET_CLOSE_REPLACED = 4001
WEBSOCKET_CLOSE_TRY_AGAIN = 1013

SIGNALING_OFFER_MESSAGE_TYPE = "sdp_offer"
SIGNALING_ANSWER_MESSAGE_TYPE = "sdp_answer"
SIGNALING_ICE_MESSAGE_TYPE = "ice_candidate"
SIGNALING_HANDSHAKE_OFFER_MESSAGE_TYPE = "handshake_offer"
SIGNALING_HANDSHAKE_ANSWER_MESSAGE_TYPE = "handshake_answer"
SIGNALING_SINGLE_USE_MESSAGE_TYPES = frozenset(
    {
        SIGNALING_OFFER_MESSAGE_TYPE,
        SIGNALING_ANSWER_MESSAGE_TYPE,
        SIGNALING_HANDSHAKE_OFFER_MESSAGE_TYPE,
        SIGNALING_HANDSHAKE_ANSWER_MESSAGE_TYPE,
    }
)
SIGNALING_MESSAGE_TYPES = frozenset(
    {
        SIGNALING_OFFER_MESSAGE_TYPE,
        SIGNALING_ANSWER_MESSAGE_TYPE,
        SIGNALING_ICE_MESSAGE_TYPE,
        SIGNALING_HANDSHAKE_OFFER_MESSAGE_TYPE,
        SIGNALING_HANDSHAKE_ANSWER_MESSAGE_TYPE,
    }
)
SIGNALING_ACTIVE_STATUSES = frozenset(
    {"offered", "accepted", "negotiating", "connected", "transferring"}
)


class WebSocketTicketRepositoryPort(Protocol):
    """Repository operations needed by the ticket HTTP and socket routes."""

    async def create(
        self,
        account_id: UUID,
        session_id: UUID,
        token_hash: bytes,
        expires_at: datetime,
    ) -> WebSocketTicketRecord: ...

    async def consume_for_socket(self, token_hash: bytes) -> WebSocketTicketRecord | None: ...


class CurrentSessionRepositoryPort(Protocol):
    """The current-session lookup required after ticket consumption."""

    async def find_current_by_id(self, session_id: UUID) -> SessionRecord | None: ...


class DeviceRepositoryPort(Protocol):
    """The account-scoped device lookup used to render presence safely."""

    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None: ...


class TransferRepositoryPort(Protocol):
    """Transfer lookup and negotiation transition required by signaling."""

    async def get_by_id(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None: ...

    async def mark_negotiating(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None: ...


class ConnectionLimitError(RuntimeError):
    """Raised when an account already has its maximum active sockets."""


@dataclass(frozen=True, slots=True)
class ActiveConnection:
    """One admitted socket bound to one authenticated application session."""

    id: UUID
    account_id: UUID
    device_id: UUID
    session_id: UUID
    websocket: WebSocket
    connected_at: datetime
    last_heartbeat_at: datetime


@dataclass(slots=True)
class _OutboundQueue:
    """One bounded writer queue owned by an admitted socket."""

    queue: asyncio.Queue[dict[str, object]]
    task: asyncio.Task[None] | None = None
    failed: bool = False
    queued_bytes: int = 0
    in_flight: int = 0


@dataclass(slots=True)
class _SignalingUsage:
    """Per-transfer signaling accounting held only while a transfer stays live."""

    account_id: UUID
    updated_at: datetime
    total: int = 0
    counts: dict[tuple[UUID, str], int] = field(default_factory=dict)


class WebSocketTicketService:
    """Issue short-lived opaque tickets without persisting their raw value."""

    def __init__(
        self,
        repository: WebSocketTicketRepositoryPort,
        *,
        clock: Callable[[], datetime] | None = None,
        lifetime: timedelta = WEBSOCKET_TICKET_LIFETIME,
    ) -> None:
        if lifetime <= timedelta(0):
            raise ValueError("ticket lifetime must be positive")
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lifetime = lifetime

    async def issue(self, session: SessionRecord) -> tuple[str, WebSocketTicketRecord]:
        """Create a ticket bound to the authenticated session."""

        issued_at = _utc_now(self._clock())
        raw_ticket = new_opaque_token()
        record = await self._repository.create(
            session.user_id,
            session.id,
            hash_secret(raw_ticket),
            issued_at + self._lifetime,
        )
        return raw_ticket, record


# A descriptive compatibility name for callers that prefer an issuer noun.
WebSocketTicketIssuer = WebSocketTicketService


class PresenceManager:
    """Track one current socket per account/device and fan out presence."""

    def __init__(
        self,
        device_repository: DeviceRepositoryPort | None = None,
        session_repository: CurrentSessionRepositoryPort | None = None,
        transfer_repository: TransferRepositoryPort | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        heartbeat_timeout: timedelta = PRESENCE_HEARTBEAT_TIMEOUT,
        metrics: RuntimeMetrics | None = None,
    ) -> None:
        if heartbeat_timeout <= timedelta(0):
            raise ValueError("heartbeat timeout must be positive")
        self._device_repository = device_repository
        self._session_repository = session_repository
        self._transfer_repository = transfer_repository
        self._clock = clock or (lambda: datetime.now(UTC))
        self._heartbeat_timeout = heartbeat_timeout
        self._metrics = metrics or RuntimeMetrics()
        self._connections: dict[UUID, dict[UUID, ActiveConnection]] = {}
        self._outbound: dict[UUID, _OutboundQueue] = {}
        self._signaling: dict[UUID, _SignalingUsage] = {}
        self._signaling_account_totals: dict[UUID, int] = {}
        self._lock = asyncio.Lock()

    @property
    def metrics(self) -> RuntimeMetrics:
        """Return coarse resource counters for this manager."""

        return self._metrics

    async def register(self, connection: ActiveConnection) -> ActiveConnection | None:
        """Register a socket and return the replaced socket for that device."""

        previous_outbound: _OutboundQueue | None = None
        async with self._lock:
            account_connections = self._connections.setdefault(connection.account_id, {})
            previous = account_connections.get(connection.device_id)
            if previous is None and not self._has_connection_capacity(account_connections):
                if not account_connections:
                    del self._connections[connection.account_id]
                self._metrics.increment("socket_connection_rejected")
                raise ConnectionLimitError
            account_connections[connection.device_id] = connection
            if previous is not None:
                previous_outbound = self._outbound.pop(previous.id, None)
            queue = _OutboundQueue(asyncio.Queue(maxsize=MAX_WEBSOCKET_QUEUE_MESSAGES))
            queue.task = asyncio.create_task(self._drain_outbound(connection, queue))
            self._outbound[connection.id] = queue
        await self._stop_outbound(previous_outbound)
        self._metrics.increment("socket_registered")
        return previous

    def _has_connection_capacity(self, account_connections: dict[UUID, ActiveConnection]) -> bool:
        """Return whether one more socket fits the account and process-wide limits."""

        return (
            len(account_connections) < MAX_CONNECTIONS_PER_ACCOUNT
            and self.active_socket_count() < MAX_TOTAL_CONNECTIONS
        )

    def active_socket_count(self) -> int:
        """Return the number of sockets currently registered across all accounts."""

        return sum(len(sockets) for sockets in self._connections.values())

    async def remove(self, connection: ActiveConnection) -> bool:
        """Remove a socket only when it is still the current device socket."""

        outbound: _OutboundQueue | None = None
        async with self._lock:
            account_connections = self._connections.get(connection.account_id)
            if account_connections is None:
                return False
            current = account_connections.get(connection.device_id)
            if current is None or current.id != connection.id:
                return False
            del account_connections[connection.device_id]
            if not account_connections:
                del self._connections[connection.account_id]
            outbound = self._outbound.pop(connection.id, None)
        await self._stop_outbound(outbound)
        return True

    async def heartbeat(self, connection: ActiveConnection) -> ActiveConnection | None:
        """Refresh a socket heartbeat after rechecking its session when available."""

        if self._session_repository is not None:
            current_session = await self._session_repository.find_current_by_id(
                connection.session_id
            )
            if current_session is None or current_session.user_id != connection.account_id:
                await self.remove(connection)
                return None
        now = _utc_now(self._clock())
        async with self._lock:
            account_connections = self._connections.get(connection.account_id)
            current_connection = (
                None
                if account_connections is None
                else account_connections.get(connection.device_id)
            )
            if current_connection is None or current_connection.id != connection.id:
                return None
            updated = replace(current_connection, last_heartbeat_at=now)
            if account_connections is None:
                return None
            account_connections[connection.device_id] = updated
            return updated

    async def online_connections(self, account_id: UUID) -> list[ActiveConnection]:
        """Return a snapshot of the account's current connections."""

        await self.prune_expired(account_id)
        async with self._lock:
            return list(self._connections.get(account_id, {}).values())

    async def connection_for(
        self,
        account_id: UUID,
        device_id: UUID,
    ) -> ActiveConnection | None:
        """Return one current, heartbeat-checked connection for an account device."""

        await self.prune_expired(account_id)
        async with self._lock:
            account_connections = self._connections.get(account_id)
            return None if account_connections is None else account_connections.get(device_id)

    async def send_to_device(
        self,
        account_id: UUID,
        device_id: UUID,
        payload: dict[str, object],
    ) -> bool:
        """Send a bounded control-plane payload only to an account-owned socket."""

        connection = await self.connection_for(account_id, device_id)
        if connection is None:
            return False
        return await self._enqueue_outbound(connection, payload)

    async def _enqueue_outbound(
        self,
        connection: ActiveConnection,
        payload: dict[str, object],
    ) -> bool:
        """Queue one payload for a live socket, closing it when the queue overflows."""

        size = _payload_bytes(payload)
        async with self._lock:
            current = self._connections.get(connection.account_id, {}).get(connection.device_id)
            outbound = self._outbound.get(connection.id)
            if (
                current is None
                or current.id != connection.id
                or outbound is None
                or outbound.failed
            ):
                return False
            if (
                outbound.queue.qsize() >= MAX_WEBSOCKET_QUEUE_MESSAGES
                or outbound.queued_bytes + size > MAX_WEBSOCKET_QUEUE_BYTES
            ):
                outbound.failed = True
                self._metrics.increment("socket_queue_rejected")
            else:
                outbound.queue.put_nowait(payload)
                outbound.queued_bytes += size
                return True
        await self._drop(connection)
        return False

    async def _drain_outbound(
        self,
        connection: ActiveConnection,
        outbound: _OutboundQueue,
    ) -> None:
        """Write queued payloads one at a time so a slow socket cannot block senders."""

        while True:
            payload = await outbound.queue.get()
            async with self._lock:
                outbound.queued_bytes = max(0, outbound.queued_bytes - _payload_bytes(payload))
                outbound.in_flight += 1
            try:
                await asyncio.wait_for(
                    connection.websocket.send_json(payload),
                    timeout=WEBSOCKET_SEND_TIMEOUT_SECONDS,
                )
            except asyncio.CancelledError:
                outbound.failed = True
                raise
            except TimeoutError:
                self._metrics.increment("socket_send_timeout")
                await self._fail_outbound(connection, outbound)
                return
            except Exception:
                self._metrics.increment("socket_send_failed")
                await self._fail_outbound(connection, outbound)
                return
            async with self._lock:
                outbound.in_flight -= 1

    async def _fail_outbound(
        self,
        connection: ActiveConnection,
        outbound: _OutboundQueue,
    ) -> None:
        async with self._lock:
            outbound.failed = True
            outbound.in_flight -= 1
        await self._drop(connection)

    async def flush_outbound(
        self,
        timeout: float = WEBSOCKET_SEND_TIMEOUT_SECONDS,
    ) -> bool:
        """Wait for queued payloads to be written, bounded by ``timeout``."""

        async def drained() -> None:
            while await self._outbound_pending():
                await asyncio.sleep(0)

        try:
            await asyncio.wait_for(drained(), timeout=timeout)
        except TimeoutError:
            return False
        return True

    async def _outbound_pending(self) -> bool:
        async with self._lock:
            return any(
                not outbound.queue.empty() or outbound.in_flight > 0
                for outbound in self._outbound.values()
            )

    async def _drop(self, connection: ActiveConnection) -> None:
        """Release one socket's state and close it with a retryable code."""

        await self.remove(connection)
        await _close(connection.websocket, WEBSOCKET_CLOSE_TRY_AGAIN)

    async def forward_signaling(
        self,
        connection: ActiveConnection,
        message: dict[str, object],
    ) -> bool:
        """Validate and forward one typed signaling message to its selected peer.

        The current socket's authenticated account and device are always the source
        of routing.  Device identifiers supplied by the browser are accepted only
        when they exactly describe the account-owned transfer in the repository.
        """

        repository = self._transfer_repository
        if repository is None:
            self._metrics.increment("signaling_rejected")
            return False
        await self._prune_signaling_state(_utc_now(self._clock()))
        parsed = _parse_signaling_message(message, self._clock())
        if parsed is None:
            self._metrics.increment("signaling_rejected")
            return False
        transfer_id, sender_device_id, recipient_device_id, message_type = parsed
        transfer = await repository.get_by_id(connection.account_id, transfer_id)
        if transfer is None or not _active_transfer(transfer, self._clock()):
            if transfer is not None:
                await self._clear_signaling_state(transfer.id)
            self._metrics.increment("signaling_rejected")
            return False
        message_expiry = _message_expiry(message.get("expires_at"), self._clock())
        if message_expiry is None or message_expiry > transfer.expires_at:
            self._metrics.increment("signaling_rejected")
            return False
        if (
            transfer.protocol_version != message["v"]
            or transfer.sender_device_id != sender_device_id
            or transfer.recipient_device_id != recipient_device_id
            or connection.device_id not in (sender_device_id, recipient_device_id)
        ):
            self._metrics.increment("signaling_rejected")
            return False

        if message_type == SIGNALING_OFFER_MESSAGE_TYPE:
            if connection.device_id != sender_device_id or transfer.status not in {
                "accepted",
                "negotiating",
            }:
                self._metrics.increment("signaling_rejected")
                return False
            if transfer.status == "accepted":
                transition = getattr(repository, "mark_negotiating", None)
                if not callable(transition):
                    self._metrics.increment("signaling_rejected")
                    return False
                negotiating = await transition(connection.account_id, transfer.id)
                if negotiating is None:
                    self._metrics.increment("signaling_rejected")
                    return False
        elif message_type in {
            SIGNALING_ANSWER_MESSAGE_TYPE,
            SIGNALING_HANDSHAKE_ANSWER_MESSAGE_TYPE,
        }:
            if connection.device_id != recipient_device_id or transfer.status != "negotiating":
                self._metrics.increment("signaling_rejected")
                return False
        elif message_type == SIGNALING_HANDSHAKE_OFFER_MESSAGE_TYPE:
            if connection.device_id != sender_device_id or transfer.status not in {
                "accepted",
                "negotiating",
            }:
                self._metrics.increment("signaling_rejected")
                return False
            if transfer.status == "accepted":
                transition = getattr(repository, "mark_negotiating", None)
                if not callable(transition):
                    self._metrics.increment("signaling_rejected")
                    return False
                negotiating = await transition(connection.account_id, transfer.id)
                if negotiating is None:
                    self._metrics.increment("signaling_rejected")
                    return False
        elif transfer.status not in {"accepted", "negotiating"}:
            self._metrics.increment("signaling_rejected")
            return False

        if not await self._record_signaling_use(transfer.id, connection, message_type):
            self._metrics.increment("signaling_rejected")
            return False

        target_device_id = (
            recipient_device_id if connection.device_id == sender_device_id else sender_device_id
        )
        forwarded = await self.send_to_device(connection.account_id, target_device_id, message)
        if not forwarded:
            self._metrics.increment("signaling_rejected")
            return False
        self._metrics.increment("signaling_forwarded")
        return True

    async def online_devices(self, account_id: UUID) -> list[dict[str, object]]:
        """Return only active, account-owned device metadata for online sockets."""

        connections = await self.online_connections(account_id)
        devices: list[dict[str, object]] = []
        for connection in sorted(connections, key=lambda item: str(item.device_id)):
            device = await self._device(connection.account_id, connection.device_id)
            if device is None or device.status != "active":
                continue
            devices.append({"device_id": str(device.id), "label": device.label})
        return devices

    async def broadcast_presence(self, account_id: UUID) -> None:
        """Notify only sockets belonging to the changed account."""

        payload: dict[str, object] = {
            "type": PRESENCE_EVENT_TYPE,
            "devices": await self.online_devices(account_id),
        }
        for connection in await self.online_connections(account_id):
            await self._enqueue_outbound(connection, payload)

    async def disconnect_device(self, account_id: UUID, device_id: UUID) -> None:
        """Close and remove the current socket for one account-owned device."""

        outbound: _OutboundQueue | None = None
        async with self._lock:
            account_connections = self._connections.get(account_id)
            if account_connections is None:
                connection = None
            else:
                connection = account_connections.get(device_id)
                if connection is not None:
                    del account_connections[device_id]
                    if not account_connections:
                        del self._connections[account_id]
                    outbound = self._outbound.pop(connection.id, None)
        if connection is not None:
            await self._stop_outbound(outbound)
            await _close(connection.websocket, WEBSOCKET_CLOSE_POLICY)
            await self.broadcast_presence(account_id)

    async def disconnect_account(self, account_id: UUID) -> None:
        """Close every current socket for one account."""

        async with self._lock:
            connections = list(self._connections.pop(account_id, {}).values())
        for connection in connections:
            await _close(connection.websocket, WEBSOCKET_CLOSE_POLICY)

    async def close_all(self) -> None:
        """Close all sockets during application shutdown."""

        async with self._lock:
            connections = [
                connection
                for account_connections in self._connections.values()
                for connection in account_connections.values()
            ]
            outbound = list(self._outbound.values())
            self._connections.clear()
            self._outbound.clear()
            self._signaling.clear()
            self._signaling_account_totals.clear()
        for queue in outbound:
            await self._stop_outbound(queue)
        for connection in connections:
            await _close(connection.websocket, 1001)

    async def prune_expired(self, account_id: UUID | None = None) -> None:
        """Remove sockets that have missed the bounded heartbeat window."""

        now = _utc_now(self._clock())
        async with self._lock:
            account_ids = [account_id] if account_id is not None else list(self._connections)
            expired: list[ActiveConnection] = []
            for current_account_id in account_ids:
                account_connections = self._connections.get(current_account_id)
                if account_connections is None:
                    continue
                for device_id, connection in list(account_connections.items()):
                    if connection.last_heartbeat_at + self._heartbeat_timeout <= now:
                        expired.append(connection)
                        del account_connections[device_id]
                if not account_connections:
                    self._connections.pop(current_account_id, None)
        for connection in expired:
            async with self._lock:
                outbound = self._outbound.pop(connection.id, None)
            await self._stop_outbound(outbound)
            self._metrics.increment("socket_heartbeat_timeout")
            await _close(connection.websocket, WEBSOCKET_CLOSE_HEARTBEAT_TIMEOUT)

        await self._prune_signaling_state(now)

    async def cleanup(self) -> dict[str, int]:
        """Prune stale sockets and signaling state and return coarse counts."""

        before = self._metrics.value("signaling_state_cleaned")
        await self.prune_expired()
        after = self._metrics.value("signaling_state_cleaned")
        return {"signaling_state": after - before}

    async def _stop_outbound(self, outbound: _OutboundQueue | None) -> None:
        if outbound is None:
            return
        outbound.failed = True
        outbound.queued_bytes = 0
        while True:
            try:
                outbound.queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        task = outbound.task
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _prune_signaling_state(self, now: datetime) -> None:
        cutoff = _utc_now(now) - SIGNALING_STATE_RETENTION
        async with self._lock:
            stale_transfers = [
                transfer_id
                for transfer_id, usage in self._signaling.items()
                if usage.updated_at <= cutoff
            ]
            for transfer_id in stale_transfers:
                self._release_signaling(transfer_id)
        if stale_transfers:
            self._metrics.increment("signaling_state_cleaned", len(stale_transfers))

    async def _record_signaling_use(
        self,
        transfer_id: UUID,
        connection: ActiveConnection,
        message_type: str,
    ) -> bool:
        """Charge one message against its transfer, device, and account budgets."""

        maximum = (
            1
            if message_type in SIGNALING_SINGLE_USE_MESSAGE_TYPES
            else MAX_SIGNALING_ICE_CANDIDATES
        )
        count_key = (connection.device_id, message_type)
        async with self._lock:
            usage = self._signaling.get(transfer_id)
            if usage is None:
                usage = _SignalingUsage(
                    account_id=connection.account_id,
                    updated_at=_utc_now(self._clock()),
                )
                self._signaling[transfer_id] = usage
            account_total = self._signaling_account_totals.get(connection.account_id, 0)
            if (
                usage.counts.get(count_key, 0) >= maximum
                or usage.total >= MAX_SIGNALING_MESSAGES
                or account_total >= MAX_SIGNALING_MESSAGES_PER_ACCOUNT
            ):
                return False
            usage.counts[count_key] = usage.counts.get(count_key, 0) + 1
            usage.total += 1
            usage.updated_at = _utc_now(self._clock())
            self._signaling_account_totals[connection.account_id] = account_total + 1
            return True

    def _release_signaling(self, transfer_id: UUID) -> bool:
        """Release one transfer's signaling budget. Callers must hold the lock."""

        usage = self._signaling.pop(transfer_id, None)
        if usage is None:
            return False
        remaining = self._signaling_account_totals.get(usage.account_id, 0) - usage.total
        if remaining > 0:
            self._signaling_account_totals[usage.account_id] = remaining
        else:
            self._signaling_account_totals.pop(usage.account_id, None)
        return True

    async def release_transfer(self, transfer_id: UUID) -> None:
        """Release signaling budgets once a transfer reaches a terminal state."""

        await self._clear_signaling_state(transfer_id)

    async def _clear_signaling_state(self, transfer_id: UUID) -> None:
        async with self._lock:
            cleared = self._release_signaling(transfer_id)
        if cleared:
            self._metrics.increment("signaling_state_cleaned")

    async def _device(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None:
        if self._device_repository is None:
            return None
        return await self._device_repository.get_by_id(account_id, device_id)


# Keep the shorter name available to callers that think in terms of sockets.
WebSocketConnectionManager = PresenceManager
ConnectionManager = PresenceManager


def public_ticket(record: WebSocketTicketRecord, raw_ticket: str) -> dict[str, object]:
    """Serialize the one-time ticket without exposing its stored digest."""

    return {
        "ticket": raw_ticket,
        "ticket_id": str(record.id),
        "expires_at": record.expires_at,
    }


def _utc_now(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("presence timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _ticket_hash(value: str | None) -> bytes | None:
    if value is None or not 1 <= len(value) <= 512:
        return None
    if any(ord(character) < 32 for character in value):
        return None
    try:
        return hash_secret(value)
    except (UnicodeEncodeError, ValueError):
        return None


def _query_ticket(websocket: WebSocket) -> str | None:
    values = websocket.query_params.getlist("ticket")
    return values[0] if len(values) == 1 else None


def _payload_bytes(payload: dict[str, object]) -> int:
    """Return the encoded size used for outbound queue accounting."""

    try:
        return len(json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return MAX_WEBSOCKET_QUEUE_BYTES + 1


async def _close(websocket: WebSocket, code: int) -> None:
    try:
        await asyncio.wait_for(
            websocket.close(code=code),
            timeout=WEBSOCKET_SEND_TIMEOUT_SECONDS,
        )
    except (Exception, TimeoutError):
        return


def _json_object_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON object members before routing a socket message."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def _canonical_uuid(value: object) -> UUID | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError):
        return None
    return parsed if str(parsed) == value else None


def _message_expiry(value: object, now: datetime) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    try:
        expires_at = datetime.fromtimestamp(value / 1000, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return expires_at if expires_at > _utc_now(now) else None


def _active_transfer(record: TransferRequestRecord, now: datetime) -> bool:
    return record.status in SIGNALING_ACTIVE_STATUSES and record.expires_at > _utc_now(now)


def _parse_signaling_message(
    message: dict[str, object],
    now: datetime,
) -> tuple[UUID, UUID, UUID, str] | None:
    """Validate the small, typed envelope used for signaling forwarding."""

    message_type = message.get("type")
    if message_type not in SIGNALING_MESSAGE_TYPES:
        return None
    if isinstance(message.get("v"), bool) or message.get("v") != 1:
        return None
    transfer_id = _canonical_uuid(message.get("transfer_id"))
    sender_device_id = _canonical_uuid(message.get("sender_device_id"))
    recipient_device_id = _canonical_uuid(message.get("recipient_device_id"))
    if transfer_id is None or sender_device_id is None or recipient_device_id is None:
        return None
    if sender_device_id == recipient_device_id:
        return None
    if _message_expiry(message.get("expires_at"), now) is None:
        return None

    envelope = {
        "type",
        "v",
        "transfer_id",
        "sender_device_id",
        "recipient_device_id",
        "expires_at",
    }
    if message_type in {SIGNALING_OFFER_MESSAGE_TYPE, SIGNALING_ANSWER_MESSAGE_TYPE}:
        if set(message) != envelope | {"sdp"}:
            return None
        sdp = message.get("sdp")
        if not isinstance(sdp, str) or not sdp:
            return None
        if len(sdp.encode("utf-8")) > MAX_SIGNALING_SDP_BYTES:
            return None
    elif message_type in {
        SIGNALING_HANDSHAKE_OFFER_MESSAGE_TYPE,
        SIGNALING_HANDSHAKE_ANSWER_MESSAGE_TYPE,
    }:
        if set(message) != envelope | {"handshake"}:
            return None
        handshake = message.get("handshake")
        if not isinstance(handshake, dict) or set(handshake) != {"core", "signature"}:
            return None
        signature = handshake.get("signature")
        core = handshake.get("core")
        if (
            not isinstance(signature, str)
            or not signature
            or len(signature.encode("utf-8")) > 256
            or not isinstance(core, dict)
            or not core
            or len(json.dumps(handshake, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
            > MAX_SIGNALING_HANDSHAKE_BYTES
        ):
            return None
        expected_core_type = (
            "handshake_offer"
            if message_type == SIGNALING_HANDSHAKE_OFFER_MESSAGE_TYPE
            else "handshake_answer"
        )
        if core.get("type") != expected_core_type or core.get("v") != 1:
            return None
        if (
            core.get("transfer_id") != str(transfer_id)
            or core.get("sender_device_id") != str(sender_device_id)
            or core.get("recipient_device_id") != str(recipient_device_id)
        ):
            return None
    else:
        allowed = envelope | {"candidate", "sdp_mid", "sdp_mline_index", "username_fragment"}
        if not set(message).issubset(allowed) or "candidate" not in message:
            return None
        candidate = message.get("candidate")
        if (
            not isinstance(candidate, str)
            or not candidate
            or len(candidate.encode("utf-8")) > MAX_SIGNALING_ICE_CANDIDATE_BYTES
        ):
            return None
        for key in ("sdp_mid", "username_fragment"):
            value = message.get(key)
            if value is not None and (
                not isinstance(value, str) or len(value.encode("utf-8")) > 128
            ):
                return None
        line_index = message.get("sdp_mline_index")
        if line_index is not None and (
            isinstance(line_index, bool) or not isinstance(line_index, int) or line_index < 0
        ):
            return None
        if isinstance(line_index, int) and line_index > 65535:
            return None
    return transfer_id, sender_device_id, recipient_device_id, cast(str, message_type)


def _ticket_repository(request: Request) -> WebSocketTicketRepositoryPort:
    repository = getattr(request.app.state, "websocket_ticket_repository", None)
    if repository is None:
        raise RuntimeError("WebSocket ticket repository is not configured")
    return cast(WebSocketTicketRepositoryPort, repository)


def _ticket_service(request: Request) -> WebSocketTicketService:
    service = getattr(request.app.state, "websocket_ticket_service", None)
    if isinstance(service, WebSocketTicketService):
        return service
    service = WebSocketTicketService(_ticket_repository(request))
    request.app.state.websocket_ticket_service = service
    return service


def _session_repository(request: Request) -> CurrentSessionRepositoryPort:
    repository = getattr(request.app.state, "session_repository", None)
    if repository is None:
        raise RuntimeError("session repository is not configured")
    return cast(CurrentSessionRepositoryPort, repository)


def _presence_manager(request: Request) -> PresenceManager:
    manager = getattr(request.app.state, "presence_manager", None)
    if not isinstance(manager, PresenceManager):
        raise RuntimeError("presence manager is not configured")
    return manager


def _websocket_origin_allowed(websocket: WebSocket) -> bool:
    settings = getattr(websocket.app.state, "settings", None)
    origin = websocket.headers.get("origin")
    return settings is not None and origin == settings.app_origin


async def _serve_connection(
    websocket: WebSocket,
    connection: ActiveConnection,
    manager: PresenceManager,
) -> None:
    received = 0
    while True:
        if received >= MAX_SOCKET_MESSAGES:
            manager.metrics.increment("socket_message_budget_exhausted")
            await _close(websocket, WEBSOCKET_CLOSE_POLICY)
            return
        received += 1
        try:
            raw_message = await asyncio.wait_for(
                websocket.receive_text(),
                timeout=manager._heartbeat_timeout.total_seconds(),
            )
        except TimeoutError:
            await _close(websocket, WEBSOCKET_CLOSE_HEARTBEAT_TIMEOUT)
            return
        except WebSocketDisconnect:
            return
        except RuntimeError:
            await _close(websocket, WEBSOCKET_CLOSE_UNSUPPORTED_DATA)
            return

        if len(raw_message.encode("utf-8")) > MAX_WEBSOCKET_MESSAGE_BYTES:
            await _close(websocket, WEBSOCKET_CLOSE_MESSAGE_TOO_LARGE)
            return
        try:
            message = json.loads(raw_message, object_pairs_hook=_json_object_no_duplicates)
        except (TypeError, ValueError):
            await _close(websocket, WEBSOCKET_CLOSE_UNSUPPORTED_DATA)
            return
        if not isinstance(message, dict):
            await _close(websocket, WEBSOCKET_CLOSE_UNSUPPORTED_DATA)
            return

        message_type = message.get("type")
        if message_type == HEARTBEAT_MESSAGE_TYPE and set(message) == {"type"}:
            updated = await manager.heartbeat(connection)
            if updated is None:
                await _close(websocket, WEBSOCKET_CLOSE_POLICY)
                return
            connection = updated
            await websocket.send_json({"type": HEARTBEAT_MESSAGE_TYPE})
        elif message_type == PING_MESSAGE_TYPE and set(message) == {"type"}:
            await websocket.send_json({"type": PONG_MESSAGE_TYPE})
        elif message_type in SIGNALING_MESSAGE_TYPES:
            if not await manager.forward_signaling(connection, message):
                await _close(websocket, WEBSOCKET_CLOSE_POLICY)
                return
        else:
            await _close(websocket, WEBSOCKET_CLOSE_UNSUPPORTED_DATA)
            return


router = APIRouter(prefix="/auth", tags=["presence"])


@router.post("/websocket/ticket")
@router.post("/socket-ticket")
async def issue_websocket_ticket(
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    """Issue a short-lived ticket through the authenticated HTTP boundary."""

    try:
        raw_ticket, record = await _ticket_service(request).issue(session)
    except (RuntimeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        ) from error
    return public_ticket(record, raw_ticket)


@router.get("/devices/online")
@router.get("/presence")
async def list_online_devices(
    request: Request,
    session: Annotated[SessionRecord, Depends(get_authenticated_session)],
) -> dict[str, object]:
    """List only online devices belonging to the authenticated account."""

    check_optional_origin(request)
    return {"devices": await _presence_manager(request).online_devices(session.user_id)}


@router.websocket("/ws")
@router.websocket("/websocket")
async def websocket_presence(websocket: WebSocket) -> None:
    """Admit one ticket-authenticated socket and serve presence heartbeats."""

    if not _websocket_origin_allowed(websocket):
        await _close(websocket, WEBSOCKET_CLOSE_POLICY)
        return
    ticket_hash = _ticket_hash(_query_ticket(websocket))
    if ticket_hash is None:
        await _close(websocket, WEBSOCKET_CLOSE_POLICY)
        return

    ticket_repository = getattr(websocket.app.state, "websocket_ticket_repository", None)
    session_repository = getattr(websocket.app.state, "session_repository", None)
    manager = getattr(websocket.app.state, "presence_manager", None)
    if (
        ticket_repository is None
        or session_repository is None
        or not isinstance(manager, PresenceManager)
    ):
        await _close(websocket, status.WS_1011_INTERNAL_ERROR)
        return
    if manager._transfer_repository is None:
        manager._transfer_repository = getattr(websocket.app.state, "transfer_repository", None)
    consumer = getattr(ticket_repository, "consume_for_socket", None)
    lookup = getattr(session_repository, "find_current_by_id", None)
    if not callable(consumer) or not callable(lookup):
        await _close(websocket, status.WS_1011_INTERNAL_ERROR)
        return
    ticket = await cast(
        Awaitable[WebSocketTicketRecord | None],
        consumer(ticket_hash),
    )
    if ticket is None:
        await _close(websocket, WEBSOCKET_CLOSE_POLICY)
        return
    session = await cast(
        Awaitable[SessionRecord | None],
        lookup(ticket.session_id),
    )
    if session is None:
        await _close(websocket, WEBSOCKET_CLOSE_POLICY)
        return

    await websocket.accept()
    now = _utc_now(manager._clock())
    connection = ActiveConnection(
        id=uuid4(),
        account_id=session.user_id,
        device_id=session.device_id,
        session_id=session.id,
        websocket=websocket,
        connected_at=now,
        last_heartbeat_at=now,
    )
    try:
        previous = await manager.register(connection)
    except ConnectionLimitError:
        await _close(websocket, WEBSOCKET_CLOSE_TRY_AGAIN)
        return
    if previous is not None:
        await _close(previous.websocket, WEBSOCKET_CLOSE_REPLACED)
    await manager.broadcast_presence(session.user_id)
    try:
        await _serve_connection(websocket, connection, manager)
    finally:
        if await manager.remove(connection):
            await manager.broadcast_presence(session.user_id)


__all__ = [
    "ActiveConnection",
    "ConnectionLimitError",
    "ConnectionManager",
    "HEARTBEAT_MESSAGE_TYPE",
    "MAX_ICE_CANDIDATE_BYTES",
    "MAX_ICE_CANDIDATES_PER_TRANSFER",
    "MAX_HANDSHAKE_BYTES",
    "MAX_SIGNALING_ICE_CANDIDATE_BYTES",
    "MAX_SIGNALING_ICE_CANDIDATES",
    "MAX_SIGNALING_HANDSHAKE_BYTES",
    "MAX_SIGNALING_MESSAGES",
    "MAX_SIGNALING_SDP_BYTES",
    "MAX_SOCKET_QUEUE_MESSAGES",
    "MAX_CONNECTIONS_PER_ACCOUNT",
    "MAX_CONNECTIONS_PER_DEVICE",
    "MAX_SIGNALING_MESSAGES_PER_ACCOUNT",
    "MAX_SOCKET_MESSAGES",
    "MAX_TOTAL_CONNECTIONS",
    "MAX_WEBSOCKET_QUEUE_BYTES",
    "MAX_WEBSOCKET_QUEUE_MESSAGES",
    "MAX_WEBSOCKET_MESSAGE_BYTES",
    "MAX_SDP_BYTES",
    "PING_MESSAGE_TYPE",
    "PONG_MESSAGE_TYPE",
    "PRESENCE_EVENT_TYPE",
    "PRESENCE_HEARTBEAT_TIMEOUT",
    "PresenceManager",
    "SIGNALING_ANSWER_MESSAGE_TYPE",
    "SIGNALING_HANDSHAKE_ANSWER_MESSAGE_TYPE",
    "SIGNALING_HANDSHAKE_OFFER_MESSAGE_TYPE",
    "SIGNALING_ICE_MESSAGE_TYPE",
    "SIGNALING_MESSAGE_TYPES",
    "SIGNALING_OFFER_MESSAGE_TYPE",
    "TransferRepositoryPort",
    "WebSocketConnectionManager",
    "WebSocketTicketIssuer",
    "WebSocketTicketService",
    "WEBSOCKET_TICKET_LIFETIME",
    "WEBSOCKET_CLOSE_TRY_AGAIN",
    "SIGNALING_SINGLE_USE_MESSAGE_TYPES",
    "WEBSOCKET_SEND_TIMEOUT_SECONDS",
    "SIGNALING_STATE_RETENTION",
    "issue_websocket_ticket",
    "list_online_devices",
    "public_ticket",
    "router",
    "websocket_presence",
]
