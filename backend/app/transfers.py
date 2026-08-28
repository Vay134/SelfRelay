"""Generic transfer offers and account-scoped transfer control operations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Protocol
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from .presence import PresenceManager
from .repositories.models import SessionRecord, TransferRequestRecord
from .security import check_optional_origin
from .session_api import get_authenticated_session, require_session_csrf

TRANSFER_PROTOCOL_VERSION = 1
TRANSFER_REQUEST_LIFETIME = timedelta(minutes=10)
TRANSFER_ACTIVE_STATUSES = frozenset(
    {"offered", "accepted", "negotiating", "connected", "transferring"}
)

TRANSFER_UNAVAILABLE_MESSAGE = "The transfer is unavailable."
TRANSFER_INVALID_MESSAGE = "The transfer request is invalid."


class TransferRepositoryPort(Protocol):
    """Repository operations required by transfer control routes."""

    async def get_by_id(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None: ...

    async def list_for_account(self, account_id: UUID) -> list[TransferRequestRecord]: ...

    async def create(
        self,
        account_id: UUID,
        sender_device_id: UUID,
        recipient_device_id: UUID,
        protocol_version: int,
        expires_at: datetime,
    ) -> TransferRequestRecord: ...

    async def accept(
        self,
        account_id: UUID,
        transfer_id: UUID,
        recipient_device_id: UUID,
    ) -> TransferRequestRecord | None: ...

    async def reject(
        self,
        account_id: UUID,
        transfer_id: UUID,
        recipient_device_id: UUID,
    ) -> TransferRequestRecord | None: ...

    async def cancel(
        self,
        account_id: UUID,
        transfer_id: UUID,
        actor_device_id: UUID,
    ) -> TransferRequestRecord | None: ...

    async def expire(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None: ...


class DeviceLookupPort(Protocol):
    async def get_by_id(self, account_id: UUID, device_id: UUID) -> object | None: ...


class TransferError(ValueError):
    """Raised when transfer state or ownership cannot satisfy an operation."""


def _utc_now(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("transfer timestamps must be timezone-aware")
    return value.astimezone(UTC)


def public_transfer(record: TransferRequestRecord) -> dict[str, object]:
    """Serialize only generic transfer metadata safe for the control plane."""

    return {
        "v": record.protocol_version,
        "transfer_id": str(record.id),
        "sender_device_id": str(record.sender_device_id),
        "recipient_device_id": str(record.recipient_device_id),
        "status": record.status,
        "created_at": record.created_at,
        "expires_at": record.expires_at,
    }


def transfer_notification(
    record: TransferRequestRecord,
    message_type: str,
) -> dict[str, object]:
    """Build a metadata-only WebSocket notification."""

    return {
        "type": message_type,
        "v": record.protocol_version,
        "transfer_id": str(record.id),
        "sender_device_id": str(record.sender_device_id),
        "recipient_device_id": str(record.recipient_device_id),
        "created_at": record.created_at,
        "expires_at": record.expires_at,
    }


class TransferService:
    """Coordinate repository transitions and best-effort socket notifications."""

    def __init__(
        self,
        repository: TransferRepositoryPort,
        presence_manager: PresenceManager | None = None,
        device_repository: DeviceLookupPort | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        lifetime: timedelta = TRANSFER_REQUEST_LIFETIME,
    ) -> None:
        if lifetime <= timedelta(0):
            raise ValueError("transfer lifetime must be positive")
        self._repository = repository
        self._presence_manager = presence_manager
        self._device_repository = device_repository
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lifetime = lifetime

    async def create_offer(
        self,
        account_id: UUID,
        sender_device_id: UUID,
        recipient_device_id: UUID,
        protocol_version: int = TRANSFER_PROTOCOL_VERSION,
    ) -> TransferRequestRecord:
        """Create one generic offer and notify its selected recipient if online."""

        if protocol_version != TRANSFER_PROTOCOL_VERSION:
            raise TransferError("unsupported transfer protocol")
        if sender_device_id == recipient_device_id:
            raise TransferError("sender and recipient must differ")
        await self._validate_devices(account_id, sender_device_id, recipient_device_id)
        now = _utc_now(self._clock())
        record = await self._repository.create(
            account_id,
            sender_device_id,
            recipient_device_id,
            protocol_version,
            now + self._lifetime,
        )
        await self._notify(
            account_id,
            recipient_device_id,
            transfer_notification(record, "transfer_offer"),
        )
        return record

    async def accept(
        self,
        account_id: UUID,
        transfer_id: UUID,
        recipient_device_id: UUID,
    ) -> TransferRequestRecord:
        """Accept one unexpired offer from its intended recipient device."""

        current = await self._current_or_expire(account_id, transfer_id)
        if current is None or current.status != "offered":
            raise TransferError("offer is unavailable")
        accepted = await self._repository.accept(account_id, transfer_id, recipient_device_id)
        if accepted is None:
            raise TransferError("offer is unavailable")
        await self._notify(
            account_id,
            accepted.sender_device_id,
            transfer_notification(accepted, "transfer_accepted"),
        )
        return accepted

    async def reject(
        self,
        account_id: UUID,
        transfer_id: UUID,
        recipient_device_id: UUID,
    ) -> TransferRequestRecord:
        """Reject one unexpired offer from its intended recipient device."""

        current = await self._current_or_expire(account_id, transfer_id)
        if current is None or current.status != "offered":
            raise TransferError("offer is unavailable")
        rejected = await self._repository.reject(account_id, transfer_id, recipient_device_id)
        if rejected is None:
            raise TransferError("offer is unavailable")
        await self._notify(
            account_id,
            rejected.sender_device_id,
            transfer_notification(rejected, "transfer_rejected"),
        )
        return rejected

    async def cancel(
        self,
        account_id: UUID,
        transfer_id: UUID,
        actor_device_id: UUID,
    ) -> TransferRequestRecord:
        """Cancel one active transfer from either participating device."""

        current = await self._current_or_expire(account_id, transfer_id)
        if current is None or current.status not in TRANSFER_ACTIVE_STATUSES:
            raise TransferError("transfer is unavailable")
        cancelled = await self._repository.cancel(account_id, transfer_id, actor_device_id)
        if cancelled is None:
            raise TransferError("transfer is unavailable")
        await self._notify_participants(
            account_id,
            cancelled,
            transfer_notification(cancelled, "transfer_cancelled"),
        )
        return cancelled

    async def expire(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord:
        """Mark one stale active transfer expired and notify both participants."""

        expired = await self._repository.expire(account_id, transfer_id)
        if expired is None:
            raise TransferError("transfer is not stale or is unavailable")
        await self._notify_participants(
            account_id,
            expired,
            transfer_notification(expired, "transfer_expired"),
        )
        return expired

    async def get(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord:
        """Return a transfer, atomically expiring it when its deadline passed."""

        record = await self._current_or_expire(account_id, transfer_id)
        if record is None:
            raise TransferError("transfer is unavailable")
        return record

    async def list(self, account_id: UUID) -> list[TransferRequestRecord]:
        """Return account transfers, expiring stale active records as encountered."""

        records = await self._repository.list_for_account(account_id)
        result: list[TransferRequestRecord] = []
        for record in records:
            if record.status in TRANSFER_ACTIVE_STATUSES and record.expires_at <= _utc_now(
                self._clock()
            ):
                try:
                    record = await self.expire(account_id, record.id)
                except TransferError:
                    refreshed = await self._repository.get_by_id(account_id, record.id)
                    if refreshed is not None:
                        record = refreshed
            result.append(record)
        return result

    async def _current_or_expire(
        self,
        account_id: UUID,
        transfer_id: UUID,
    ) -> TransferRequestRecord | None:
        record = await self._repository.get_by_id(account_id, transfer_id)
        if record is None or record.status not in TRANSFER_ACTIVE_STATUSES:
            return record
        if record.expires_at > _utc_now(self._clock()):
            return record
        try:
            return await self.expire(account_id, transfer_id)
        except TransferError:
            return await self._repository.get_by_id(account_id, transfer_id)

    async def _validate_devices(
        self,
        account_id: UUID,
        sender_device_id: UUID,
        recipient_device_id: UUID,
    ) -> None:
        if self._device_repository is None:
            return
        sender = await self._device_repository.get_by_id(account_id, sender_device_id)
        recipient = await self._device_repository.get_by_id(account_id, recipient_device_id)
        if (
            sender is None
            or recipient is None
            or getattr(sender, "status", None) != "active"
            or getattr(recipient, "status", None) != "active"
            or getattr(sender, "epoch", None) != getattr(recipient, "epoch", None)
        ):
            raise TransferError("transfer devices are unavailable")

    async def _notify_participants(
        self,
        account_id: UUID,
        record: TransferRequestRecord,
        payload: dict[str, object],
    ) -> None:
        await self._notify(account_id, record.sender_device_id, payload)
        if record.recipient_device_id != record.sender_device_id:
            await self._notify(account_id, record.recipient_device_id, payload)

    async def _notify(
        self,
        account_id: UUID,
        device_id: UUID,
        payload: dict[str, object],
    ) -> None:
        if self._presence_manager is None:
            return
        await self._presence_manager.send_to_device(account_id, device_id, payload)


class TransferCreateRequest(BaseModel):
    """Generic offer input; it deliberately has no file metadata fields."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    recipient_device_id: UUID | None = Field(default=None)
    recipient_id: UUID | None = Field(default=None)
    device_id: UUID | None = Field(default=None)
    protocol_version: int = Field(default=TRANSFER_PROTOCOL_VERSION, ge=1, le=1)
    v: int | None = Field(default=None, ge=1, le=1)

    def resolved_recipient(self) -> UUID:
        values = {
            value
            for value in (self.recipient_device_id, self.recipient_id, self.device_id)
            if value is not None
        }
        if len(values) != 1:
            raise ValueError("one recipient device is required")
        if self.v is not None and self.v != self.protocol_version:
            raise ValueError("protocol versions do not match")
        return next(iter(values))


def _service_from_request(request: Request) -> TransferService:
    service = getattr(request.app.state, "transfer_service", None)
    if not isinstance(service, TransferService):
        raise RuntimeError("transfer service is not configured")
    return service


def _public_response(record: TransferRequestRecord, action: str) -> dict[str, object]:
    public = public_transfer(record)
    return {
        **public,
        "transfer": public,
        "status": record.status,
        action: True,
    }


def _unavailable(error: Exception) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=TRANSFER_UNAVAILABLE_MESSAGE,
    )


router = APIRouter(tags=["transfers"])


@router.post("/auth/transfers")
@router.post("/transfers")
@router.post("/auth/transfers/offer")
@router.post("/transfers/offer")
@router.post("/auth/transfer")
@router.post("/transfer")
async def create_transfer_offer(
    payload: TransferCreateRequest,
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    """Create and notify a generic transfer offer."""

    try:
        recipient_device_id = payload.resolved_recipient()
        record = await _service_from_request(request).create_offer(
            session.user_id,
            session.device_id,
            recipient_device_id,
            payload.protocol_version,
        )
    except (TransferError, RuntimeError, TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=TRANSFER_INVALID_MESSAGE,
        ) from error
    return _public_response(record, "offered")


@router.get("/auth/transfers")
@router.get("/transfers")
async def list_transfers(
    request: Request,
    session: Annotated[SessionRecord, Depends(get_authenticated_session)],
) -> dict[str, object]:
    """List only generic transfer metadata owned by the authenticated account."""

    check_optional_origin(request)
    records = await _service_from_request(request).list(session.user_id)
    return {"transfers": [public_transfer(record) for record in records]}


@router.get("/auth/transfers/{transfer_id}")
@router.get("/transfers/{transfer_id}")
async def get_transfer(
    transfer_id: UUID,
    request: Request,
    session: Annotated[SessionRecord, Depends(get_authenticated_session)],
) -> dict[str, object]:
    """Return one account-owned transfer and apply expiry when necessary."""

    check_optional_origin(request)
    try:
        record = await _service_from_request(request).get(session.user_id, transfer_id)
    except TransferError as error:
        raise _unavailable(error) from error
    return public_transfer(record)


@router.post("/auth/transfers/{transfer_id}/accept")
@router.post("/transfers/{transfer_id}/accept")
@router.post("/auth/transfer/{transfer_id}/accept")
@router.post("/transfer/{transfer_id}/accept")
async def accept_transfer(
    transfer_id: UUID,
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    """Accept one generic offer from its intended recipient device."""

    try:
        record = await _service_from_request(request).accept(
            session.user_id,
            transfer_id,
            session.device_id,
        )
    except (TransferError, RuntimeError, TypeError, ValueError) as error:
        raise _unavailable(error) from error
    return _public_response(record, "accepted")


@router.post("/auth/transfers/{transfer_id}/reject")
@router.post("/transfers/{transfer_id}/reject")
@router.post("/auth/transfer/{transfer_id}/reject")
@router.post("/transfer/{transfer_id}/reject")
async def reject_transfer(
    transfer_id: UUID,
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    """Reject one generic offer from its intended recipient device."""

    try:
        record = await _service_from_request(request).reject(
            session.user_id,
            transfer_id,
            session.device_id,
        )
    except (TransferError, RuntimeError, TypeError, ValueError) as error:
        raise _unavailable(error) from error
    return _public_response(record, "rejected")


@router.post("/auth/transfers/{transfer_id}/cancel")
@router.post("/transfers/{transfer_id}/cancel")
@router.post("/auth/transfer/{transfer_id}/cancel")
@router.post("/transfer/{transfer_id}/cancel")
async def cancel_transfer(
    transfer_id: UUID,
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    """Cancel one active transfer from either participating device."""

    try:
        record = await _service_from_request(request).cancel(
            session.user_id,
            transfer_id,
            session.device_id,
        )
    except (TransferError, RuntimeError, TypeError, ValueError) as error:
        raise _unavailable(error) from error
    return _public_response(record, "cancelled")


@router.post("/auth/transfers/{transfer_id}/expire")
@router.post("/transfers/{transfer_id}/expire")
@router.post("/auth/transfer/{transfer_id}/expire")
@router.post("/transfer/{transfer_id}/expire")
async def expire_transfer(
    transfer_id: UUID,
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    """Apply the server-side expiry transition to a stale account transfer."""

    try:
        record = await _service_from_request(request).expire(session.user_id, transfer_id)
    except (TransferError, RuntimeError, TypeError, ValueError) as error:
        raise _unavailable(error) from error
    return _public_response(record, "expired")


__all__ = [
    "TRANSFER_ACTIVE_STATUSES",
    "TRANSFER_INVALID_MESSAGE",
    "TRANSFER_PROTOCOL_VERSION",
    "TRANSFER_REQUEST_LIFETIME",
    "TRANSFER_UNAVAILABLE_MESSAGE",
    "TransferCreateRequest",
    "TransferError",
    "TransferRepositoryPort",
    "TransferService",
    "create_transfer_offer",
    "get_transfer",
    "list_transfers",
    "public_transfer",
    "reject_transfer",
    "router",
    "transfer_notification",
]
