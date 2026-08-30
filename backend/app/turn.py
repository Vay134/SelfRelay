"""Authorized issuance of short-lived TURN credentials."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Protocol, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from .adapters import (
    TurnCredentialProvider,
    TurnCredentialProviderError,
    TurnCredentialRequest,
    TurnCredentials,
)
from .auth import RATE_LIMIT_MESSAGE, RateLimiterPort
from .metrics import RuntimeMetrics
from .repositories.models import DeviceRecord, SessionRecord, TransferRequestRecord
from .session_api import require_session_csrf
from .transfers import TRANSFER_ACTIVE_STATUSES, TransferError, TransferService

TURN_CREDENTIAL_TTL_SECONDS = 5 * 60
TURN_CREDENTIAL_ISSUE_WINDOW = timedelta(minutes=10)
TURN_CREDENTIAL_ACCOUNT_LIMIT = 20
TURN_CREDENTIAL_DEVICE_LIMIT = 10
TURN_CREDENTIAL_TRANSFER_LIMIT = 6
TURN_CREDENTIAL_NETWORK_LIMIT = 30
TURN_CREDENTIAL_ELIGIBLE_STATUSES = TRANSFER_ACTIVE_STATUSES

TURN_UNAVAILABLE_MESSAGE = "The transfer is unavailable."
TURN_PROVIDER_UNAVAILABLE_MESSAGE = "TURN credentials are temporarily unavailable."
TURN_RATE_LIMIT_MESSAGE = RATE_LIMIT_MESSAGE


class DeviceLookupPort(Protocol):
    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None: ...


class TurnAuthorizationError(ValueError):
    """Raised when a session cannot use TURN for the requested transfer."""


class TurnCredentialRateLimitedError(RuntimeError):
    """Raised when a TURN credential issuance bucket is exhausted."""


class TurnProviderUnavailableError(RuntimeError):
    """Raised when the configured TURN provider cannot issue credentials."""


def _utc_now(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("TURN timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _network_identifier(value: str) -> str:
    """Bound the value used as a rate-limit input without persisting it raw."""

    normalized = value.strip() if isinstance(value, str) else ""
    return normalized[:256] or "unknown"


class TurnCredentialService:
    """Authorize one participant and issue credentials through the provider port."""

    def __init__(
        self,
        provider: TurnCredentialProvider,
        transfer_service: TransferService,
        device_repository: DeviceLookupPort,
        rate_limiter: RateLimiterPort,
        *,
        clock: Callable[[], datetime] | None = None,
        metrics: RuntimeMetrics | None = None,
    ) -> None:
        self._provider = provider
        self._transfer_service = transfer_service
        self._device_repository = device_repository
        self._rate_limiter = rate_limiter
        self._clock = clock or (lambda: datetime.now(UTC))
        self._metrics = metrics or RuntimeMetrics()

    @property
    def metrics(self) -> RuntimeMetrics:
        """Return coarse issuance counters for this service."""

        return self._metrics

    async def issue(
        self,
        session: SessionRecord,
        transfer_id: UUID,
        network_identifier: str,
    ) -> TurnCredentials:
        """Issue credentials for an active participant before recipient acceptance."""

        current = _utc_now(self._clock())
        try:
            transfer = await self._transfer_service.get(session.user_id, transfer_id)
        except TransferError as error:
            self._metrics.increment("turn_credential_denied")
            raise TurnAuthorizationError from error
        if not self._transfer_is_eligible(transfer, current, session.device_id):
            self._metrics.increment("turn_credential_denied")
            raise TurnAuthorizationError

        actor = await self._device_repository.get_by_id(session.user_id, session.device_id)
        peer_device_id = (
            transfer.recipient_device_id
            if transfer.sender_device_id == session.device_id
            else transfer.sender_device_id
        )
        peer = await self._device_repository.get_by_id(session.user_id, peer_device_id)
        if not self._device_is_eligible(actor, session) or not self._peer_is_eligible(
            peer,
            actor,
        ):
            self._metrics.increment("turn_credential_denied")
            raise TurnAuthorizationError

        allowed = self._rate_limiter.allow_many(
            (
                (
                    "turn:credential:account",
                    str(session.user_id),
                    TURN_CREDENTIAL_ACCOUNT_LIMIT,
                    TURN_CREDENTIAL_ISSUE_WINDOW,
                ),
                (
                    "turn:credential:device",
                    str(session.device_id),
                    TURN_CREDENTIAL_DEVICE_LIMIT,
                    TURN_CREDENTIAL_ISSUE_WINDOW,
                ),
                (
                    "turn:credential:transfer",
                    str(transfer.id),
                    TURN_CREDENTIAL_TRANSFER_LIMIT,
                    TURN_CREDENTIAL_ISSUE_WINDOW,
                ),
                (
                    "turn:credential:network",
                    _network_identifier(network_identifier),
                    TURN_CREDENTIAL_NETWORK_LIMIT,
                    TURN_CREDENTIAL_ISSUE_WINDOW,
                ),
            ),
            now=current,
        )
        if not isinstance(allowed, bool):
            allowed = await cast(Awaitable[bool], allowed)
        if not allowed:
            self._metrics.increment("turn_credential_rate_limited")
            raise TurnCredentialRateLimitedError

        try:
            credentials = await self._provider.issue_credentials(
                TurnCredentialRequest(
                    account_id=str(session.user_id),
                    device_id=str(session.device_id),
                    transfer_id=str(transfer.id),
                    ttl_seconds=TURN_CREDENTIAL_TTL_SECONDS,
                )
            )
        except TurnCredentialProviderError as error:
            self._metrics.increment("turn_provider_failed")
            raise TurnProviderUnavailableError from error
        self._metrics.increment("turn_credential_issued")
        return credentials

    @staticmethod
    def _transfer_is_eligible(
        transfer: TransferRequestRecord,
        current: datetime,
        device_id: UUID,
    ) -> bool:
        return (
            transfer.status in TURN_CREDENTIAL_ELIGIBLE_STATUSES
            and transfer.expires_at > current
            and device_id in (transfer.sender_device_id, transfer.recipient_device_id)
        )

    @staticmethod
    def _device_is_eligible(
        device: DeviceRecord | None,
        session: SessionRecord,
    ) -> bool:
        return (
            device is not None
            and device.user_id == session.user_id
            and device.id == session.device_id
            and device.status == "active"
            and device.epoch == session.epoch
        )

    @staticmethod
    def _peer_is_eligible(
        peer: DeviceRecord | None,
        actor: DeviceRecord | None,
    ) -> bool:
        return (
            peer is not None
            and actor is not None
            and peer.user_id == actor.user_id
            and peer.status == "active"
            and peer.epoch == actor.epoch
        )


def _service_from_request(request: Request) -> TurnCredentialService:
    service = getattr(request.app.state, "turn_credential_service", None)
    if not isinstance(service, TurnCredentialService):
        raise RuntimeError("TURN credential service is not configured")
    return service


def _request_network_identifier(request: Request) -> str:
    client = request.client
    return "unknown" if client is None or not client.host else client.host


def public_turn_credentials(credentials: TurnCredentials) -> dict[str, object]:
    """Serialize provider credentials into a browser RTC configuration fragment."""

    return {
        "ice_servers": [
            {
                "urls": list(credentials.urls),
                "username": credentials.username,
                "credential": credentials.credential,
            }
        ],
        "expires_at": credentials.expires_at,
    }


router = APIRouter(tags=["turn"])


@router.post("/auth/transfers/{transfer_id}/turn-credentials")
async def issue_turn_credentials(
    transfer_id: UUID,
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    """Issue short-lived TURN credentials for an accepted transfer participant."""

    try:
        credentials = await _service_from_request(request).issue(
            session,
            transfer_id,
            _request_network_identifier(request),
        )
    except TurnCredentialRateLimitedError as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=TURN_RATE_LIMIT_MESSAGE,
        ) from error
    except TurnAuthorizationError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=TURN_UNAVAILABLE_MESSAGE,
        ) from error
    except TurnProviderUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=TURN_PROVIDER_UNAVAILABLE_MESSAGE,
        ) from error
    return public_turn_credentials(credentials)


__all__ = [
    "TURN_CREDENTIAL_ACCOUNT_LIMIT",
    "TURN_CREDENTIAL_DEVICE_LIMIT",
    "TURN_CREDENTIAL_ELIGIBLE_STATUSES",
    "TURN_CREDENTIAL_ISSUE_WINDOW",
    "TURN_CREDENTIAL_NETWORK_LIMIT",
    "TURN_CREDENTIAL_TTL_SECONDS",
    "TURN_CREDENTIAL_TRANSFER_LIMIT",
    "TURN_PROVIDER_UNAVAILABLE_MESSAGE",
    "TURN_RATE_LIMIT_MESSAGE",
    "TURN_UNAVAILABLE_MESSAGE",
    "TurnAuthorizationError",
    "TurnCredentialRateLimitedError",
    "TurnCredentialService",
    "TurnProviderUnavailableError",
    "issue_turn_credentials",
    "public_turn_credentials",
    "router",
]
