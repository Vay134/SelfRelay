"""WebSocket ticket admission and in-process account presence."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
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

from .repositories.models import DeviceRecord, SessionRecord, WebSocketTicketRecord
from .security import check_optional_origin
from .session_api import get_authenticated_session, require_session_csrf
from .sessions import hash_secret, new_opaque_token

WEBSOCKET_TICKET_LIFETIME = timedelta(minutes=1)
PRESENCE_HEARTBEAT_TIMEOUT = timedelta(seconds=45)
MAX_WEBSOCKET_MESSAGE_BYTES = 4096

PRESENCE_EVENT_TYPE = "presence"
HEARTBEAT_MESSAGE_TYPE = "heartbeat"
PING_MESSAGE_TYPE = "ping"
PONG_MESSAGE_TYPE = "pong"

WEBSOCKET_CLOSE_POLICY = 1008
WEBSOCKET_CLOSE_UNSUPPORTED_DATA = 1003
WEBSOCKET_CLOSE_MESSAGE_TOO_LARGE = 1009
WEBSOCKET_CLOSE_HEARTBEAT_TIMEOUT = 4008
WEBSOCKET_CLOSE_REPLACED = 4001


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
        *,
        clock: Callable[[], datetime] | None = None,
        heartbeat_timeout: timedelta = PRESENCE_HEARTBEAT_TIMEOUT,
    ) -> None:
        if heartbeat_timeout <= timedelta(0):
            raise ValueError("heartbeat timeout must be positive")
        self._device_repository = device_repository
        self._session_repository = session_repository
        self._clock = clock or (lambda: datetime.now(UTC))
        self._heartbeat_timeout = heartbeat_timeout
        self._connections: dict[UUID, dict[UUID, ActiveConnection]] = {}
        self._lock = asyncio.Lock()

    async def register(self, connection: ActiveConnection) -> ActiveConnection | None:
        """Register a socket and return the replaced socket for that device."""

        async with self._lock:
            account_connections = self._connections.setdefault(connection.account_id, {})
            previous = account_connections.get(connection.device_id)
            account_connections[connection.device_id] = connection
            return previous

    async def remove(self, connection: ActiveConnection) -> bool:
        """Remove a socket only when it is still the current device socket."""

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

        payload = {
            "type": PRESENCE_EVENT_TYPE,
            "devices": await self.online_devices(account_id),
        }
        targets = await self.online_connections(account_id)
        failed: list[ActiveConnection] = []
        for connection in targets:
            try:
                await connection.websocket.send_json(payload)
            except Exception:
                failed.append(connection)
        for connection in failed:
            await self.remove(connection)

    async def disconnect_device(self, account_id: UUID, device_id: UUID) -> None:
        """Close and remove the current socket for one account-owned device."""

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
        if connection is not None:
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
            self._connections.clear()
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
            await _close(connection.websocket, WEBSOCKET_CLOSE_HEARTBEAT_TIMEOUT)

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


async def _close(websocket: WebSocket, code: int) -> None:
    try:
        await websocket.close(code=code)
    except Exception:
        return


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
    while True:
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
            message = json.loads(raw_message)
        except (TypeError, ValueError):
            await _close(websocket, WEBSOCKET_CLOSE_UNSUPPORTED_DATA)
            return
        if not isinstance(message, dict) or set(message) != {"type"}:
            await _close(websocket, WEBSOCKET_CLOSE_UNSUPPORTED_DATA)
            return

        message_type = message.get("type")
        if message_type == HEARTBEAT_MESSAGE_TYPE:
            updated = await manager.heartbeat(connection)
            if updated is None:
                await _close(websocket, WEBSOCKET_CLOSE_POLICY)
                return
            connection = updated
            await websocket.send_json({"type": HEARTBEAT_MESSAGE_TYPE})
        elif message_type == PING_MESSAGE_TYPE:
            await websocket.send_json({"type": PONG_MESSAGE_TYPE})
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
    previous = await manager.register(connection)
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
    "ConnectionManager",
    "HEARTBEAT_MESSAGE_TYPE",
    "MAX_WEBSOCKET_MESSAGE_BYTES",
    "PING_MESSAGE_TYPE",
    "PONG_MESSAGE_TYPE",
    "PRESENCE_EVENT_TYPE",
    "PRESENCE_HEARTBEAT_TIMEOUT",
    "PresenceManager",
    "WebSocketConnectionManager",
    "WebSocketTicketIssuer",
    "WebSocketTicketService",
    "WEBSOCKET_TICKET_LIFETIME",
    "issue_websocket_ticket",
    "list_online_devices",
    "public_ticket",
    "router",
    "websocket_presence",
]
