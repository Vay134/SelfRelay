"""Creation of short-lived requests to enroll a new trusted browser."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Protocol
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from .auth import normalize_email
from .device_auth import MAX_DEVICE_LABEL_LENGTH, normalize_device_label
from .device_crypto import (
    DeviceCryptoError,
    canonical_public_key,
    decode_base64url,
    encode_base64url,
    fingerprint_public_key,
)
from .repositories.models import AccountRecord, PairingRequestRecord
from .security import require_exact_origin
from .sessions import hash_secret

PAIRING_REQUEST_LIFETIME = timedelta(minutes=10)
PAIRING_COMPARISON_CODE_LENGTH = 6
PAIRING_REQUEST_MESSAGE = "If the account exists, a pairing request has been created."
PAIRING_REQUEST_INVALID_MESSAGE = "The pairing request is invalid."


class PairingRequestError(ValueError):
    """Raised when a pairing request cannot be safely created."""


class PairingAccountStore(Protocol):
    async def get_by_email(self, email_normalized: str) -> AccountRecord | None: ...


class PairingRequestStore(Protocol):
    async def create(
        self,
        account_id: UUID,
        requested_public_key_spki: bytes,
        requested_fingerprint: bytes,
        requested_label: str,
        request_nonce: bytes,
        comparison_code_hash: bytes,
        expires_at: datetime,
    ) -> PairingRequestRecord: ...


@dataclass(frozen=True, slots=True)
class PairingRequestResult:
    """Safe creation response plus the comparison code returned exactly once."""

    request: PairingRequestRecord | None
    request_id: UUID
    requested_fingerprint: bytes
    request_nonce: bytes
    comparison_code: str
    created_at: datetime
    expires_at: datetime


def generate_comparison_code() -> str:
    """Generate a six-digit code that is easy to compare on two screens."""

    return str(secrets.randbelow(10**PAIRING_COMPARISON_CODE_LENGTH)).zfill(
        PAIRING_COMPARISON_CODE_LENGTH
    )


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    current = clock()
    if current.tzinfo is None:
        raise ValueError("pairing timestamps must be timezone-aware")
    return current.astimezone(UTC)


class PairingRequestService:
    """Validate a new browser key and persist a pending pairing request."""

    def __init__(
        self,
        account_store: PairingAccountStore,
        request_store: PairingRequestStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.account_store = account_store
        self.request_store = request_store
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        return _utc_now(self._clock)

    async def create_request(
        self,
        email: str,
        public_key_spki: bytes,
        label: str,
        *,
        fingerprint: bytes | None = None,
    ) -> PairingRequestResult:
        """Create a pending request without creating an application session."""

        try:
            email_normalized = normalize_email(email)
            normalized_key = canonical_public_key(bytes(public_key_spki))
            calculated_fingerprint = fingerprint_public_key(normalized_key)
            normalized_label = normalize_device_label(label)
        except (DeviceCryptoError, TypeError, ValueError) as error:
            raise PairingRequestError from error

        if fingerprint is not None:
            if not isinstance(fingerprint, bytes | bytearray):
                raise PairingRequestError
            supplied_fingerprint = bytes(fingerprint)
            if len(supplied_fingerprint) != len(calculated_fingerprint) or not hmac.compare_digest(
                supplied_fingerprint,
                calculated_fingerprint,
            ):
                raise PairingRequestError

        now = self._now()
        expires_at = now + PAIRING_REQUEST_LIFETIME
        comparison_code = generate_comparison_code()
        request_nonce = secrets.token_bytes(32)
        account = await self.account_store.get_by_email(email_normalized)
        if account is None:
            # Keep the public contract identical for unknown accounts. This metadata is
            # deliberately not persisted, so it cannot be used to create a session later.
            return PairingRequestResult(
                request=None,
                request_id=uuid4(),
                requested_fingerprint=calculated_fingerprint,
                request_nonce=request_nonce,
                comparison_code=comparison_code,
                created_at=now,
                expires_at=expires_at,
            )

        record = await self.request_store.create(
            account.id,
            normalized_key,
            calculated_fingerprint,
            normalized_label,
            request_nonce,
            hash_secret(comparison_code),
            expires_at,
        )
        return PairingRequestResult(
            request=record,
            request_id=record.id,
            requested_fingerprint=record.requested_fingerprint,
            request_nonce=record.request_nonce,
            comparison_code=comparison_code,
            created_at=record.created_at,
            expires_at=record.expires_at,
        )


def public_pairing_request(result: PairingRequestResult) -> dict[str, object]:
    """Serialize only values needed by the new browser to wait for approval."""

    return {
        "message": PAIRING_REQUEST_MESSAGE,
        "request_id": str(result.request_id),
        "status": "pending",
        "fingerprint": encode_base64url(result.requested_fingerprint),
        "request_nonce": encode_base64url(result.request_nonce),
        "comparison_code": result.comparison_code,
        "created_at": result.created_at,
        "expires_at": result.expires_at,
    }


class PairingRequestCreateRequest(BaseModel):
    """JSON body accepted by the unauthenticated pairing-request endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    email: str = Field(min_length=1, max_length=320)
    public_key_spki: str | None = Field(default=None, min_length=1, max_length=4096)
    public_key: str | None = Field(default=None, min_length=1, max_length=4096)
    fingerprint: str | None = Field(default=None, min_length=1, max_length=128)
    public_key_fingerprint: str | None = Field(default=None, min_length=1, max_length=128)
    label: str = Field(default="This browser", min_length=1, max_length=MAX_DEVICE_LABEL_LENGTH)


def _service_from_request(request: Request) -> PairingRequestService:
    service = getattr(request.app.state, "pairing_request_service", None)
    if not isinstance(service, PairingRequestService):
        raise RuntimeError("pairing request service is not configured")
    return service


def _decode_key(value: str) -> bytes:
    return decode_base64url(value, maximum_bytes=1024)


def _decode_fingerprint(value: str) -> bytes:
    decoded = decode_base64url(value, maximum_bytes=32)
    if len(decoded) != 32:
        raise DeviceCryptoError("fingerprint must be a SHA-256 digest")
    return decoded


def _encoded_value(primary: str | None, alias: str | None) -> str:
    if primary is not None and alias is not None and primary != alias:
        raise PairingRequestError
    value = primary or alias
    if value is None:
        raise PairingRequestError
    return value


router = APIRouter(prefix="/auth", tags=["pairing"])


@router.post("/pairing/request", status_code=status.HTTP_202_ACCEPTED)
@router.post("/pairing/requests", status_code=status.HTTP_202_ACCEPTED)
@router.post("/pairings/request", status_code=status.HTTP_202_ACCEPTED)
async def create_pairing_request(
    payload: PairingRequestCreateRequest,
    request: Request,
    _origin_check: Annotated[None, Depends(require_exact_origin)],
) -> dict[str, object]:
    """Start new-device pairing without issuing a session."""

    try:
        key_value = _encoded_value(payload.public_key_spki, payload.public_key)
        fingerprint_value = _encoded_value(
            payload.fingerprint,
            payload.public_key_fingerprint,
        ) if payload.fingerprint is not None or payload.public_key_fingerprint is not None else None
        result = await _service_from_request(request).create_request(
            payload.email,
            _decode_key(key_value),
            payload.label,
            fingerprint=(
                None
                if fingerprint_value is None
                else _decode_fingerprint(fingerprint_value)
            ),
        )
    except (DeviceCryptoError, PairingRequestError, ValueError, TypeError) as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=PAIRING_REQUEST_INVALID_MESSAGE,
        ) from error
    return public_pairing_request(result)


__all__ = [
    "PAIRING_COMPARISON_CODE_LENGTH",
    "PAIRING_REQUEST_INVALID_MESSAGE",
    "PAIRING_REQUEST_LIFETIME",
    "PAIRING_REQUEST_MESSAGE",
    "PairingRequestCreateRequest",
    "PairingRequestError",
    "PairingRequestResult",
    "PairingRequestService",
    "generate_comparison_code",
    "public_pairing_request",
    "router",
]
