"""Creation of short-lived requests to enroll a new trusted browser."""

from __future__ import annotations

import hmac
import re
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
    pairing_approval_message,
    pairing_approval_payload,
    verify_p1363_signature,
)
from .repositories.models import AccountRecord, DeviceRecord, PairingRequestRecord, SessionRecord
from .security import check_optional_origin, require_exact_origin
from .session_api import get_authenticated_session, require_session_csrf
from .sessions import hash_secret

PAIRING_REQUEST_LIFETIME = timedelta(minutes=10)
PAIRING_COMPARISON_CODE_LENGTH = 6
PAIRING_REQUEST_MESSAGE = "If the account exists, a pairing request has been created."
PAIRING_REQUEST_INVALID_MESSAGE = "The pairing request is invalid."
PAIRING_APPROVAL_FAILURE = "The pairing request could not be approved."
PAIRING_REJECTION_FAILURE = "The pairing request could not be rejected."
PAIRING_MAX_ATTEMPTS = 10
_PAIRING_CODE_RE = re.compile(r"^[0-9]{6}$")


class PairingRequestError(ValueError):
    """Raised when a pairing request cannot be safely created."""


class PairingApprovalError(ValueError):
    """Raised when a trusted-device approval cannot be safely completed."""


class PairingRejectionError(ValueError):
    """Raised when a trusted-device rejection cannot be safely completed."""


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


class PairingApprovalAccountStore(Protocol):
    async def get_by_id(self, account_id: UUID) -> AccountRecord | None: ...


class PairingApprovalDeviceStore(Protocol):
    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None: ...


class PairingApprovalStore(Protocol):
    async def list_pending_for_account(self, account_id: UUID) -> list[PairingRequestRecord]: ...

    async def record_comparison_attempt(
        self,
        account_id: UUID,
        request_id: UUID,
        maximum_attempts: int = PAIRING_MAX_ATTEMPTS,
    ) -> PairingRequestRecord | None: ...

    async def approve(
        self,
        account_id: UUID,
        request_id: UUID,
        approved_by_device_id: UUID,
        approval_signature: bytes,
    ) -> PairingRequestRecord | None: ...

    async def reject(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None: ...


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


@dataclass(frozen=True, slots=True)
class PairingApprovalResult:
    """Result of approving a pairing request from one trusted device."""

    request: PairingRequestRecord
    account: AccountRecord
    approving_device: DeviceRecord
    approval_payload: dict[str, object]


class PairingApprovalService:
    """Authorize pairing actions from a current, account-owned trusted device."""

    def __init__(
        self,
        account_store: PairingApprovalAccountStore,
        device_store: PairingApprovalDeviceStore,
        request_store: PairingApprovalStore,
        *,
        clock: Callable[[], datetime] | None = None,
        maximum_attempts: int = PAIRING_MAX_ATTEMPTS,
    ) -> None:
        if not 1 <= maximum_attempts <= 10:
            raise ValueError("maximum pairing attempts must be between 1 and 10")
        self.account_store = account_store
        self.device_store = device_store
        self.request_store = request_store
        self.maximum_attempts = maximum_attempts
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        return _utc_now(self._clock)

    async def _trusted_device(
        self,
        account_id: UUID,
        device_id: UUID,
        *,
        session: SessionRecord | None = None,
    ) -> tuple[AccountRecord, DeviceRecord]:
        account = await self.account_store.get_by_id(account_id)
        device = await self.device_store.get_by_id(account_id, device_id)
        if (
            account is None
            or device is None
            or device.user_id != account.id
            or device.status != "active"
            or device.epoch != account.device_epoch
            or (session is not None and session.epoch != account.device_epoch)
        ):
            raise PairingApprovalError
        return account, device

    async def list_pending(
        self,
        account_id: UUID,
        device_id: UUID,
        *,
        session: SessionRecord | None = None,
    ) -> list[PairingRequestRecord]:
        """List pending requests only for a current trusted device session."""

        account, _ = await self._trusted_device(account_id, device_id, session=session)
        return await self.request_store.list_pending_for_account(account.id)

    async def approve_request(
        self,
        account_id: UUID,
        device_id: UUID,
        request_id: UUID,
        comparison_code: str,
        approval_nonce: bytes,
        signature: bytes,
        *,
        session: SessionRecord | None = None,
    ) -> PairingApprovalResult:
        """Verify the comparison code and trusted-device signature before approval."""

        account, approving_device = await self._trusted_device(
            account_id,
            device_id,
            session=session,
        )
        if not isinstance(comparison_code, str) or not _PAIRING_CODE_RE.fullmatch(comparison_code):
            raise PairingApprovalError
        if not isinstance(approval_nonce, bytes | bytearray) or len(approval_nonce) != 32:
            raise PairingApprovalError
        if not isinstance(signature, bytes | bytearray) or len(signature) != 64:
            raise PairingApprovalError

        request = await self.request_store.record_comparison_attempt(
            account.id,
            request_id,
            self.maximum_attempts,
        )
        if request is None:
            raise PairingApprovalError
        try:
            supplied_hash = hash_secret(comparison_code)
        except (UnicodeEncodeError, TypeError, ValueError) as error:
            raise PairingApprovalError from error
        if not hmac.compare_digest(supplied_hash, request.comparison_code_hash):
            raise PairingApprovalError
        if request.expires_at <= self._now():
            raise PairingApprovalError

        try:
            calculated_fingerprint = fingerprint_public_key(request.requested_public_key_spki)
            if not hmac.compare_digest(calculated_fingerprint, request.requested_fingerprint):
                raise PairingApprovalError
            approval_payload = pairing_approval_payload(
                request,
                account,
                approving_device,
                approval_nonce=bytes(approval_nonce),
            )
        except (DeviceCryptoError, TypeError, ValueError) as error:
            raise PairingApprovalError from error
        if not verify_p1363_signature(
            approving_device.signing_public_key_spki,
            bytes(signature),
            pairing_approval_message(approval_payload),
        ):
            raise PairingApprovalError

        approved = await self.request_store.approve(
            account.id,
            request.id,
            approving_device.id,
            bytes(signature),
        )
        if approved is None:
            raise PairingApprovalError
        return PairingApprovalResult(
            request=approved,
            account=account,
            approving_device=approving_device,
            approval_payload=approval_payload,
        )

    async def reject_request(
        self,
        account_id: UUID,
        device_id: UUID,
        request_id: UUID,
        *,
        session: SessionRecord | None = None,
    ) -> PairingRequestRecord:
        """Reject a pending request without exposing account ownership."""

        account, _ = await self._trusted_device(account_id, device_id, session=session)
        rejected = await self.request_store.reject(account.id, request_id)
        if rejected is None:
            raise PairingRejectionError
        return rejected


def public_pairing_request_record(record: PairingRequestRecord) -> dict[str, object]:
    """Serialize request metadata safe for a trusted device to display."""

    return {
        "request_id": str(record.id),
        "status": record.status,
        "requested_label": record.requested_label,
        "requested_fingerprint": encode_base64url(record.requested_fingerprint),
        "request_nonce": encode_base64url(record.request_nonce),
        "created_at": record.created_at,
        "expires_at": record.expires_at,
    }


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


class PairingApprovalRequest(BaseModel):
    """Signed comparison-code proof submitted by the trusted device."""

    comparison_code: str = Field(
        min_length=PAIRING_COMPARISON_CODE_LENGTH,
        max_length=PAIRING_COMPARISON_CODE_LENGTH,
    )
    approval_nonce: str = Field(
        min_length=1,
        max_length=128,
    )
    signature: str = Field(
        min_length=1,
        max_length=512,
    )


def _service_from_request(request: Request) -> PairingRequestService:
    service = getattr(request.app.state, "pairing_request_service", None)
    if not isinstance(service, PairingRequestService):
        raise RuntimeError("pairing request service is not configured")
    return service


def _approval_service_from_request(request: Request) -> PairingApprovalService:
    service = getattr(request.app.state, "pairing_approval_service", None)
    if not isinstance(service, PairingApprovalService):
        raise RuntimeError("pairing approval service is not configured")
    return service


def _decode_key(value: str) -> bytes:
    return decode_base64url(value, maximum_bytes=1024)


def _decode_fingerprint(value: str) -> bytes:
    decoded = decode_base64url(value, maximum_bytes=32)
    if len(decoded) != 32:
        raise DeviceCryptoError("fingerprint must be a SHA-256 digest")
    return decoded


def _decode_nonce(value: str) -> bytes:
    decoded = decode_base64url(value, maximum_bytes=32)
    if len(decoded) != 32:
        raise DeviceCryptoError("approval nonce must contain 256 bits")
    return decoded


def _decode_signature(value: str) -> bytes:
    decoded = decode_base64url(value, maximum_bytes=64)
    if len(decoded) != 64:
        raise DeviceCryptoError("approval signature must be P1363")
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
        fingerprint_value = (
            _encoded_value(
                payload.fingerprint,
                payload.public_key_fingerprint,
            )
            if payload.fingerprint is not None or payload.public_key_fingerprint is not None
            else None
        )
        result = await _service_from_request(request).create_request(
            payload.email,
            _decode_key(key_value),
            payload.label,
            fingerprint=(
                None if fingerprint_value is None else _decode_fingerprint(fingerprint_value)
            ),
        )
    except (DeviceCryptoError, PairingRequestError, ValueError, TypeError) as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=PAIRING_REQUEST_INVALID_MESSAGE,
        ) from error
    return public_pairing_request(result)


@router.get("/pairing/requests")
@router.get("/pairings/requests")
async def list_pairing_requests(
    request: Request,
    session: Annotated[SessionRecord, Depends(get_authenticated_session)],
) -> dict[str, object]:
    """List pending pairing requests for the current trusted device."""

    check_optional_origin(request)
    try:
        records = await _approval_service_from_request(request).list_pending(
            session.user_id,
            session.device_id,
            session=session,
        )
    except PairingApprovalError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=PAIRING_APPROVAL_FAILURE,
        ) from error
    return {"requests": [public_pairing_request_record(record) for record in records]}


@router.post("/pairing/requests/{request_id}/approve")
@router.post("/pairing/request/{request_id}/approve")
@router.post("/pairings/{request_id}/approve")
async def approve_pairing_request(
    request_id: UUID,
    payload: PairingApprovalRequest,
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    """Approve one request after comparison-code and signature verification."""

    try:
        result = await _approval_service_from_request(request).approve_request(
            session.user_id,
            session.device_id,
            request_id,
            payload.comparison_code,
            _decode_nonce(payload.approval_nonce),
            _decode_signature(payload.signature),
            session=session,
        )
    except (DeviceCryptoError, PairingApprovalError, ValueError, TypeError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=PAIRING_APPROVAL_FAILURE,
        ) from error
    return {
        "request": public_pairing_request_record(result.request),
        "status": "approved",
        "approved": True,
    }


@router.post("/pairing/requests/{request_id}/reject")
@router.post("/pairing/request/{request_id}/reject")
@router.post("/pairings/{request_id}/reject")
async def reject_pairing_request(
    request_id: UUID,
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    """Reject one pending request from the current trusted device."""

    try:
        rejected = await _approval_service_from_request(request).reject_request(
            session.user_id,
            session.device_id,
            request_id,
            session=session,
        )
    except (PairingRejectionError, PairingApprovalError, ValueError, TypeError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=PAIRING_REJECTION_FAILURE,
        ) from error
    return {
        "request": public_pairing_request_record(rejected),
        "status": "rejected",
        "rejected": True,
    }


__all__ = [
    "PAIRING_APPROVAL_FAILURE",
    "PAIRING_MAX_ATTEMPTS",
    "PAIRING_REJECTION_FAILURE",
    "PAIRING_COMPARISON_CODE_LENGTH",
    "PAIRING_REQUEST_INVALID_MESSAGE",
    "PAIRING_REQUEST_LIFETIME",
    "PAIRING_REQUEST_MESSAGE",
    "PairingRequestCreateRequest",
    "PairingRequestError",
    "PairingRequestResult",
    "PairingRequestService",
    "PairingApprovalError",
    "PairingApprovalRequest",
    "PairingApprovalResult",
    "PairingApprovalService",
    "PairingRejectionError",
    "generate_comparison_code",
    "list_pairing_requests",
    "approve_pairing_request",
    "reject_pairing_request",
    "public_pairing_request_record",
    "public_pairing_request",
    "router",
]
