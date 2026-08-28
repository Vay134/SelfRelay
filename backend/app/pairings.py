"""Creation of short-lived requests to enroll a new trusted browser."""

from __future__ import annotations

import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Protocol, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from .auth import normalize_email
from .device_auth import (
    MAX_DEVICE_LABEL_LENGTH,
    DeviceAuthResult,
    normalize_device_label,
    public_auth_result,
)
from .device_crypto import (
    DeviceCryptoError,
    canonical_public_key,
    decode_base64url,
    encode_base64url,
    fingerprint_public_key,
    pairing_approval_message,
    pairing_approval_payload,
    pairing_enrollment_message,
    pairing_enrollment_payload,
    verify_p1363_signature,
)
from .repositories.models import AccountRecord, DeviceRecord, PairingRequestRecord, SessionRecord
from .security import check_optional_origin, require_exact_origin
from .session_api import get_authenticated_session, require_session_csrf, set_session_cookie
from .sessions import CreatedSession, SessionService, hash_secret

PAIRING_REQUEST_LIFETIME = timedelta(minutes=10)
PAIRING_COMPARISON_CODE_LENGTH = 6
PAIRING_REQUEST_MESSAGE = "If the account exists, a pairing request has been created."
PAIRING_REQUEST_INVALID_MESSAGE = "The pairing request is invalid."
PAIRING_APPROVAL_FAILURE = "The pairing request could not be approved."
PAIRING_REJECTION_FAILURE = "The pairing request could not be rejected."
PAIRING_ENROLLMENT_FAILURE = "The pairing enrollment failed."
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
    async def get_by_id(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None: ...

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
        approval_nonce: bytes | None = None,
    ) -> PairingRequestRecord | None: ...

    async def reject(
        self,
        account_id: UUID,
        request_id: UUID,
    ) -> PairingRequestRecord | None: ...

    async def consume(
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
            bytes(approval_nonce),
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


class PairingEnrollmentError(ValueError):
    """Raised when an approved pairing cannot enroll the requested browser."""


@dataclass(frozen=True, slots=True)
class PairingEnrollmentResult:
    """The newly enrolled device and its one-time application session."""

    request: PairingRequestRecord
    account: AccountRecord
    device: DeviceRecord
    session: CreatedSession


class PairingEnrollmentService:
    """Verify the new browser key and finalize an approved pairing exactly once."""

    def __init__(
        self,
        account_store: PairingApprovalAccountStore,
        device_store: PairingApprovalDeviceStore,
        request_store: PairingApprovalStore,
        session_service: SessionService,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.account_store = account_store
        self.device_store = device_store
        self.request_store = request_store
        self.session_service = session_service
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        return _utc_now(self._clock)

    async def _request(
        self,
        request_id: UUID,
        account_id: UUID | None,
    ) -> PairingRequestRecord:
        if account_id is None:
            lookup = getattr(self.request_store, "get_by_request_id", None)
            if not callable(lookup):
                raise PairingEnrollmentError
            record = cast(PairingRequestRecord | None, await lookup(request_id))
        else:
            record = await self.request_store.get_by_id(account_id, request_id)
        if record is None or (account_id is not None and record.user_id != account_id):
            raise PairingEnrollmentError
        return record

    async def status(
        self,
        request_id: UUID,
        *,
        account_id: UUID | None = None,
    ) -> tuple[PairingRequestRecord, AccountRecord]:
        """Return safe request status for the new browser to poll."""

        record = await self._request(request_id, account_id)
        account = await self.account_store.get_by_id(record.user_id)
        if account is None:
            raise PairingEnrollmentError
        return record, account

    async def complete_request(
        self,
        request_id: UUID,
        signature: bytes,
        *,
        account_id: UUID | None = None,
        public_key_spki: bytes | None = None,
        fingerprint: bytes | None = None,
        request_nonce: bytes | None = None,
        approval_nonce: bytes | None = None,
    ) -> PairingEnrollmentResult:
        """Complete an approved request after proving possession of its key."""

        request = await self._request(request_id, account_id)
        now = self._now()
        account = await self.account_store.get_by_id(request.user_id)
        if (
            account is None
            or account.deleted_at is not None
            or request.status != "approved"
            or request.consumed_at is not None
            or request.expires_at <= now
            or request.approval_nonce is None
            or request.approved_by_device_id is None
            or request.approval_signature is None
        ):
            raise PairingEnrollmentError
        if account_id is not None and account.id != account_id:
            raise PairingEnrollmentError

        try:
            requested_key = canonical_public_key(request.requested_public_key_spki)
            requested_fingerprint = fingerprint_public_key(requested_key)
            if not hmac.compare_digest(requested_fingerprint, request.requested_fingerprint):
                raise PairingEnrollmentError
            if public_key_spki is not None and not hmac.compare_digest(
                requested_key,
                canonical_public_key(public_key_spki),
            ):
                raise PairingEnrollmentError
            if fingerprint is not None and not hmac.compare_digest(
                requested_fingerprint,
                bytes(fingerprint),
            ):
                raise PairingEnrollmentError
            if request_nonce is not None and not hmac.compare_digest(
                request.request_nonce,
                bytes(request_nonce),
            ):
                raise PairingEnrollmentError
            if approval_nonce is not None and not hmac.compare_digest(
                request.approval_nonce,
                bytes(approval_nonce),
            ):
                raise PairingEnrollmentError
            approving_device = await self.device_store.get_by_id(
                account.id,
                request.approved_by_device_id,
            )
            if (
                approving_device is None
                or approving_device.user_id != account.id
                or approving_device.status != "active"
                or approving_device.epoch != account.device_epoch
                or len(request.approval_nonce) != 32
                or len(request.approval_signature) != 64
            ):
                raise PairingEnrollmentError
            approval_payload = pairing_approval_payload(
                request,
                account,
                approving_device,
                approval_nonce=request.approval_nonce,
            )
            if not verify_p1363_signature(
                approving_device.signing_public_key_spki,
                request.approval_signature,
                pairing_approval_message(approval_payload),
            ):
                raise PairingEnrollmentError
            enrollment_payload = pairing_enrollment_payload(
                request,
                account,
                approval_nonce=request.approval_nonce,
            )
            if not verify_p1363_signature(
                requested_key,
                bytes(signature),
                pairing_enrollment_message(enrollment_payload),
            ):
                raise PairingEnrollmentError
        except (DeviceCryptoError, TypeError, ValueError) as error:
            raise PairingEnrollmentError from error

        session_secrets, idle_expires_at, absolute_expires_at = self.session_service.prepare(
            created_at=now,
        )
        finalizer = getattr(self.request_store, "finalize_enrollment", None)
        if callable(finalizer):
            finalized = await finalizer(
                account.id,
                request.id,
                request.approved_by_device_id,
                requested_key,
                requested_fingerprint,
                request.requested_label,
                account.device_epoch,
                session_secrets.token_hash,
                session_secrets.csrf_hash,
                idle_expires_at,
                absolute_expires_at,
            )
            if finalized is None:
                raise PairingEnrollmentError
            consumed, device, session_record = finalized
        else:
            # Keep small custom test stores usable; production repositories implement
            # finalize_enrollment and therefore use one database transaction.
            consumed = await self.request_store.consume(account.id, request.id)
            if consumed is None:
                raise PairingEnrollmentError
            try:
                device = await self.device_store.create(  # type: ignore[attr-defined]
                    account.id,
                    account.device_epoch,
                    request.requested_label,
                    requested_key,
                    requested_fingerprint,
                    request.approved_by_device_id,
                )
                session_record = await self.session_service._repository.create(
                    account.id,
                    device.id,
                    session_secrets.token_hash,
                    session_secrets.csrf_hash,
                    account.device_epoch,
                    idle_expires_at,
                    absolute_expires_at,
                )
            except Exception as error:
                raise PairingEnrollmentError from error
        return PairingEnrollmentResult(
            request=consumed,
            account=account,
            device=device,
            session=CreatedSession(record=session_record, secrets=session_secrets),
        )

    async def complete_pairing(
        self,
        account_id: UUID,
        request_id: UUID,
        public_key_spki: bytes,
        signature: bytes,
        fingerprint: bytes | None = None,
        request_nonce: bytes | None = None,
        approval_nonce: bytes | None = None,
    ) -> PairingEnrollmentResult:
        """Compatibility entry point with the account-first service signature."""

        return await self.complete_request(
            request_id,
            signature,
            account_id=account_id,
            public_key_spki=public_key_spki,
            fingerprint=fingerprint,
            request_nonce=request_nonce,
            approval_nonce=approval_nonce,
        )


def public_pairing_request_record(record: PairingRequestRecord) -> dict[str, object]:
    """Serialize request metadata safe for a trusted device to display."""

    public: dict[str, object] = {
        "request_id": str(record.id),
        "status": record.status,
        "requested_label": record.requested_label,
        "requested_fingerprint": encode_base64url(record.requested_fingerprint),
        "request_nonce": encode_base64url(record.request_nonce),
        "created_at": record.created_at,
        "expires_at": record.expires_at,
    }
    if record.approval_nonce is not None:
        public["approval_nonce"] = encode_base64url(record.approval_nonce)
    return public


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


class PairingEnrollmentRequest(BaseModel):
    """Proof submitted by the browser whose key was approved."""

    model_config = ConfigDict(populate_by_name=True)

    account_id: UUID | None = None
    public_key_spki: str | None = Field(default=None, min_length=1, max_length=4096)
    public_key: str | None = Field(default=None, min_length=1, max_length=4096)
    fingerprint: str | None = Field(default=None, min_length=1, max_length=128)
    public_key_fingerprint: str | None = Field(default=None, min_length=1, max_length=128)
    request_nonce: str | None = Field(default=None, min_length=1, max_length=128)
    approval_nonce: str | None = Field(default=None, min_length=1, max_length=128)
    signature: str | None = Field(default=None, min_length=1, max_length=512)
    proof: str | None = Field(default=None, min_length=1, max_length=512)


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


def _enrollment_service_from_request(request: Request) -> PairingEnrollmentService:
    service = getattr(request.app.state, "pairing_enrollment_service", None)
    if not isinstance(service, PairingEnrollmentService):
        raise RuntimeError("pairing enrollment service is not configured")
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


@router.get("/pairing/requests/{request_id}")
@router.get("/pairing/request/{request_id}")
@router.get("/pairings/{request_id}")
async def pairing_request_status(
    request_id: UUID,
    request: Request,
    account_id: UUID | None = None,
) -> dict[str, object]:
    """Return the new browser's safe pairing status and proof payload."""

    check_optional_origin(request)
    try:
        record, account = await _enrollment_service_from_request(request).status(
            request_id,
            account_id=account_id,
        )
        body = public_pairing_request_record(record)
        if record.status == "pending" and record.expires_at <= datetime.now(UTC):
            body["status"] = "expired"
        if record.status == "approved" and record.approval_nonce is not None:
            body["account_id"] = str(account.id)
            body["payload"] = pairing_enrollment_payload(
                record,
                account,
                approval_nonce=record.approval_nonce,
            )
        return body
    except (DeviceCryptoError, PairingEnrollmentError, ValueError, TypeError) as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=PAIRING_ENROLLMENT_FAILURE,
        ) from error


@router.post("/pairing/requests/{request_id}/complete")
@router.post("/pairing/request/{request_id}/complete")
@router.post("/pairings/{request_id}/complete")
@router.post("/pairing/requests/{request_id}/enroll")
async def complete_pairing_request(
    request_id: UUID,
    payload: PairingEnrollmentRequest,
    request: Request,
    response: Response,
    _origin_check: Annotated[None, Depends(require_exact_origin)],
) -> dict[str, object]:
    """Verify new-device possession and issue its first application session."""

    try:
        key_value = None
        if payload.public_key_spki is not None or payload.public_key is not None:
            key_value = _encoded_value(payload.public_key_spki, payload.public_key)
        fingerprint_value = None
        if payload.fingerprint is not None or payload.public_key_fingerprint is not None:
            fingerprint_value = _encoded_value(
                payload.fingerprint,
                payload.public_key_fingerprint,
            )
        signature_value = _encoded_value(payload.signature, payload.proof)
        result = await _enrollment_service_from_request(request).complete_request(
            request_id,
            _decode_signature(signature_value),
            account_id=payload.account_id,
            public_key_spki=None if key_value is None else _decode_key(key_value),
            fingerprint=(
                None if fingerprint_value is None else _decode_fingerprint(fingerprint_value)
            ),
            request_nonce=None
            if payload.request_nonce is None
            else _decode_nonce(payload.request_nonce),
            approval_nonce=None
            if payload.approval_nonce is None
            else _decode_nonce(payload.approval_nonce),
        )
    except (DeviceCryptoError, PairingEnrollmentError, ValueError, TypeError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=PAIRING_ENROLLMENT_FAILURE,
        ) from error
    set_session_cookie(response, result.session.token)
    return public_auth_result(
        DeviceAuthResult(result.account, result.device, result.session, recovered=False)
    )


__all__ = [
    "PAIRING_APPROVAL_FAILURE",
    "PAIRING_ENROLLMENT_FAILURE",
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
    "PairingEnrollmentError",
    "PairingEnrollmentRequest",
    "PairingEnrollmentResult",
    "PairingEnrollmentService",
    "PairingRejectionError",
    "generate_comparison_code",
    "list_pairing_requests",
    "approve_pairing_request",
    "reject_pairing_request",
    "pairing_request_status",
    "complete_pairing_request",
    "public_pairing_request_record",
    "public_pairing_request",
    "router",
]
