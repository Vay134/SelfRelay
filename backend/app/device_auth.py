"""Device registration, challenge login, email fallback, and device linking.

The service deliberately keeps the browser's private key outside this module.
Only a validated SPKI public key and a one-time proof signature cross the API
boundary.  Database-backed repositories enforce account ownership and the
in-memory repositories are used only by the explicit test application.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import threading
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Annotated, Protocol, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from .auth import RATE_LIMIT_MESSAGE, RateLimiterPort, network_fingerprint
from .device_crypto import (
    DEVICE_CHALLENGE_VERSION,
    DEVICE_PROTOCOL_VERSION,
    DeviceCryptoError,
    challenge_payload,
    decode_base64url,
    encode_base64url,
    fingerprint_public_key,
    registration_payload,
    signed_message,
    verify_p1363_signature,
)
from .repositories.models import (
    AccountRecord,
    DeviceChallengeRecord,
    DeviceLinkingOtpRecord,
    DeviceRecord,
    SessionRecord,
)
from .security import check_optional_origin, require_exact_origin
from .session_api import (
    get_authenticated_session,
    public_session,
    require_session_csrf,
    set_session_cookie,
)
from .sessions import CreatedSession, SessionService

DEVICE_CHALLENGE_LIFETIME = timedelta(minutes=5)
REGISTRATION_CHALLENGE_LIFETIME = timedelta(minutes=10)
MAX_DEVICE_LABEL_LENGTH = 100
DEVICE_AUTH_FAILURE = "Device authentication failed."
DEVICE_REGISTRATION_FAILURE = "The device registration request is invalid."


class DeviceAuthError(ValueError):
    """Base error for invalid or stale device-authentication state."""


class DeviceAuthFailure(DeviceAuthError):
    """Raised for any challenge proof that cannot authenticate a device."""


class AccountStorePort(Protocol):
    async def get_by_id(self, account_id: UUID) -> AccountRecord | None: ...

    async def mark_email_fallback(
        self,
        account_id: UUID,
        at: datetime,
    ) -> AccountRecord | None: ...


class DeviceStorePort(Protocol):
    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None: ...

    async def list_for_account(self, account_id: UUID) -> list[DeviceRecord]: ...

    async def register_for_email(
        self,
        account_id: UUID,
        epoch: int,
        label: str,
        signing_public_key_spki: bytes,
        fingerprint: bytes,
        device_id: UUID,
    ) -> DeviceRecord: ...

    async def create(
        self,
        account_id: UUID,
        epoch: int,
        label: str,
        signing_public_key_spki: bytes,
        fingerprint: bytes,
        *,
        linked_by_device_id: UUID | None = None,
        device_id: UUID | None = None,
    ) -> DeviceRecord: ...

    async def touch_last_seen(
        self,
        account_id: UUID,
        device_id: UUID,
    ) -> DeviceRecord | None: ...

    async def rename(
        self,
        account_id: UUID,
        device_id: UUID,
        label: str,
    ) -> DeviceRecord | None: ...

    async def revoke_with_sessions(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "device_logout",
    ) -> DeviceRecord | None: ...

    async def revoke_all_for_account(
        self,
        account_id: UUID,
        reason: str = "device_logout",
    ) -> int: ...

    async def logout_with_sessions(
        self,
        account_id: UUID,
        device_id: UUID,
        reason: str = "logout",
    ) -> DeviceRecord | None: ...


class ChallengeStorePort(Protocol):
    async def get_by_id(
        self,
        account_id: UUID,
        challenge_id: UUID,
    ) -> DeviceChallengeRecord | None: ...

    async def create(
        self,
        account_id: UUID,
        device_id: UUID,
        nonce_hash: bytes,
        origin: str,
        expires_at: datetime,
    ) -> DeviceChallengeRecord: ...

    async def consume(
        self,
        account_id: UUID,
        challenge_id: UUID,
    ) -> DeviceChallengeRecord | None: ...

    async def mark_failed(
        self,
        account_id: UUID,
        challenge_id: UUID,
    ) -> DeviceChallengeRecord | None: ...


def normalize_device_label(value: str) -> str:
    """Normalize a user-visible label while rejecting controls and blank text."""

    if not isinstance(value, str):
        raise ValueError("device label must be text")
    label = value.strip()
    if not 1 <= len(label) <= MAX_DEVICE_LABEL_LENGTH:
        raise ValueError("device label must be between 1 and 100 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in label):
        raise ValueError("device label must not contain control characters")
    return label


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    current = clock()
    if current.tzinfo is None:
        raise ValueError("device-auth timestamps must be timezone-aware")
    return current.astimezone(UTC)


def _hash_nonce(nonce: bytes) -> bytes:
    if len(nonce) != 32:
        raise DeviceAuthFailure("challenge nonce is invalid")
    return hashlib.sha256(nonce).digest()


@dataclass(frozen=True, slots=True)
class DeviceLoginChallenge:
    """Public state returned before returning-device proof."""

    challenge: DeviceChallengeRecord
    account: AccountRecord
    device: DeviceRecord
    nonce: bytes

    @property
    def payload(self) -> dict[str, object]:
        return challenge_payload(self.challenge, self.account, self.device, nonce=self.nonce)


DEVICE_LINKING_OTP_LIFETIME = timedelta(minutes=10)
DEVICE_LINKING_OTP_LENGTH = 6
DEVICE_LINKING_RATE_LIMIT_WINDOW = timedelta(minutes=10)
DEVICE_LINKING_SECURITY_EVENT_RETENTION = timedelta(days=30)
DEVICE_LINKING_OTP_MESSAGE = "A device-linking code was created."
DEVICE_LINKING_FAILURE = "The device-linking code is invalid or expired."
EMAIL_FALLBACK_WARNING = None
_DEVICE_LINKING_OTP_RE = re.compile(r"^[0-9]{6}$")


class DeviceLinkingRateLimited(DeviceAuthError):
    """Raised when device-linking attempts exceed the configured limit."""


class DeviceLinkingOtpStorePort(Protocol):
    async def create(
        self,
        account_id: UUID,
        issuing_device_id: UUID,
        otp_hash: bytes,
        expires_at: datetime,
    ) -> DeviceLinkingOtpRecord: ...

    async def get_active_by_hash(self, otp_hash: bytes) -> DeviceLinkingOtpRecord | None: ...

    async def mark_failed(self, otp_id: UUID) -> DeviceLinkingOtpRecord | None: ...

    async def consume_and_register(
        self,
        otp_id: UUID,
        account_id: UUID,
        issuing_device_id: UUID,
        epoch: int,
        device_id: UUID,
        label: str,
        signing_public_key_spki: bytes,
        fingerprint: bytes,
    ) -> DeviceRecord | None: ...


class SecurityEventStorePort(Protocol):
    async def create(
        self,
        event_type: str,
        outcome: str,
        expires_at: datetime,
        *,
        user_id: UUID | None = None,
        device_id: UUID | None = None,
        network_fingerprint: bytes | None = None,
        details: Mapping[str, object] | None = None,
    ) -> object: ...


async def _audit_device_event(
    store: SecurityEventStorePort | None,
    event_type: str,
    outcome: str,
    now: datetime,
    *,
    user_id: UUID | None = None,
    device_id: UUID | None = None,
    network_identifier: str | None = None,
    rate_limiter: RateLimiterPort | None = None,
    details: Mapping[str, object] | None = None,
) -> None:
    if store is None:
        return
    fingerprint = None
    if network_identifier and rate_limiter is not None:
        try:
            fingerprint = network_fingerprint(network_identifier, rate_limiter.secret)
        except (AttributeError, TypeError, ValueError):
            fingerprint = None
    try:
        await store.create(
            event_type,
            outcome,
            now + DEVICE_LINKING_SECURITY_EVENT_RETENTION,
            user_id=user_id,
            device_id=device_id,
            network_fingerprint=fingerprint,
            details=details,
        )
    except Exception:
        return


@dataclass(frozen=True, slots=True)
class RegistrationChallenge:
    """Public state returned before an email or linking key proof."""

    challenge_id: UUID
    account_id: UUID
    device_id: UUID
    epoch: int
    nonce: bytes
    origin: str
    issued_at: datetime
    expires_at: datetime
    fingerprint: bytes
    fallback: bool
    enrollment_method: str
    linking_otp_id: UUID | None = None
    linked_by_device_id: UUID | None = None

    @property
    def payload(self) -> dict[str, object]:
        return registration_payload(
            challenge_id=str(self.challenge_id),
            account_id=str(self.account_id),
            device_id=str(self.device_id),
            epoch=self.epoch,
            nonce=self.nonce,
            origin=self.origin,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            fingerprint=self.fingerprint,
            fallback=self.fallback,
            enrollment_method=self.enrollment_method,
        )


@dataclass(frozen=True, slots=True)
class _RegistrationState:
    challenge: RegistrationChallenge
    public_key_spki: bytes
    label: str
    attempts: int = 0


class RegistrationChallengeStore:
    """Short-lived one-time proof challenges held outside durable storage."""

    def __init__(self, lifetime: timedelta = REGISTRATION_CHALLENGE_LIFETIME) -> None:
        if lifetime <= timedelta(0):
            raise ValueError("registration challenge lifetime must be positive")
        self._lifetime = lifetime
        self._states: dict[UUID, _RegistrationState] = {}
        self._lock = threading.Lock()

    def issue(
        self,
        account: AccountRecord,
        device_id: UUID,
        public_key_spki: bytes,
        label: str,
        origin: str,
        *,
        fallback: bool,
        enrollment_method: str,
        linking_otp_id: UUID | None = None,
        linked_by_device_id: UUID | None = None,
        issued_at: datetime,
    ) -> RegistrationChallenge:
        challenge = RegistrationChallenge(
            challenge_id=uuid4(),
            account_id=account.id,
            device_id=device_id,
            epoch=account.device_epoch,
            nonce=secrets.token_bytes(32),
            origin=origin,
            issued_at=issued_at,
            expires_at=issued_at + self._lifetime,
            fingerprint=fingerprint_public_key(public_key_spki),
            fallback=fallback,
            enrollment_method=enrollment_method,
            linking_otp_id=linking_otp_id,
            linked_by_device_id=linked_by_device_id,
        )
        with self._lock:
            self._states[challenge.challenge_id] = _RegistrationState(
                challenge=challenge,
                public_key_spki=bytes(public_key_spki),
                label=label,
            )
        return challenge

    def get(self, challenge_id: UUID, *, now: datetime) -> _RegistrationState | None:
        current = now.astimezone(UTC)
        with self._lock:
            state = self._states.get(challenge_id)
            if state is None:
                return None
            if state.challenge.expires_at <= current:
                self._states.pop(challenge_id, None)
                return None
            return state

    def mark_failed(self, challenge_id: UUID, *, now: datetime) -> None:
        current = now.astimezone(UTC)
        with self._lock:
            state = self._states.get(challenge_id)
            if state is None or state.challenge.expires_at <= current:
                self._states.pop(challenge_id, None)
                return
            self._states[challenge_id] = replace(
                state,
                attempts=min(state.attempts + 1, 10),
            )

    def consume(self, challenge_id: UUID, *, now: datetime) -> _RegistrationState | None:
        current = now.astimezone(UTC)
        with self._lock:
            state = self._states.pop(challenge_id, None)
        if state is None or state.challenge.expires_at <= current:
            return None
        return state


@dataclass(frozen=True, slots=True)
class DeviceLinkingOtpResult:
    code: str
    record: DeviceLinkingOtpRecord


@dataclass(frozen=True, slots=True)
class DeviceAuthResult:
    account: AccountRecord
    device: DeviceRecord
    session: CreatedSession
    fallback: bool = False


class DeviceAuthService:
    """Coordinate email fallback, device linking, device proof, and sessions."""

    def __init__(
        self,
        account_store: AccountStorePort,
        device_store: DeviceStorePort,
        challenge_store: ChallengeStorePort,
        session_service: SessionService,
        linking_otp_store: DeviceLinkingOtpStorePort,
        *,
        registration_store: RegistrationChallengeStore | None = None,
        clock: Callable[[], datetime] | None = None,
        bootstrap_consumer: Callable[[str], object | None] | None = None,
        bootstrap_peeker: Callable[[str], object | None] | None = None,
        rate_limiter: RateLimiterPort | None = None,
        security_event_store: SecurityEventStorePort | None = None,
    ) -> None:
        self.account_store = account_store
        self.device_store = device_store
        self.challenge_store = challenge_store
        self.session_service = session_service
        self.linking_otp_store = linking_otp_store
        self.registration_store = registration_store or RegistrationChallengeStore()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._bootstrap_consumer = bootstrap_consumer
        self._bootstrap_peeker = bootstrap_peeker
        self._rate_limiter = rate_limiter
        self._security_event_store = security_event_store

    def _now(self) -> datetime:
        return _utc_now(self._clock)

    async def _allow(
        self,
        requests: Sequence[tuple[str, str, int, timedelta]],
        *,
        now: datetime,
    ) -> bool:
        if self._rate_limiter is None:
            return True
        result = self._rate_limiter.allow_many(requests, now=now)
        if isinstance(result, Awaitable):
            result = await result
        return bool(result)

    async def issue_registration_challenge(
        self,
        bootstrap_token: str,
        public_key_spki: bytes,
        label: str,
        origin: str,
        *,
        device_id: UUID | None = None,
    ) -> RegistrationChallenge:
        """Consume verified email state and issue an email fallback challenge."""

        if self._bootstrap_consumer is None:
            raise DeviceAuthFailure("bootstrap state is not configured")
        bootstrap = (
            self._bootstrap_peeker(bootstrap_token)
            if self._bootstrap_peeker is not None
            else self._bootstrap_consumer(bootstrap_token)
        )
        if bootstrap is None:
            raise DeviceAuthFailure("bootstrap state is invalid")
        account_id = cast(UUID, getattr(bootstrap, "account_id", None))
        account = await self.account_store.get_by_id(account_id)
        if account is None or account.device_epoch != getattr(bootstrap, "device_epoch", -1):
            raise DeviceAuthFailure("bootstrap state is stale")
        try:
            normalized_key = bytes(public_key_spki)
            fingerprint_public_key(normalized_key)
            normalized_label = normalize_device_label(label)
        except (DeviceCryptoError, TypeError, ValueError) as error:
            raise DeviceAuthFailure("device registration values are invalid") from error
        existing = await self.device_store.list_for_account(account.id)
        if self._bootstrap_peeker is not None:
            consumed = self._bootstrap_consumer(bootstrap_token)
            if consumed is None:
                raise DeviceAuthFailure("bootstrap state is invalid")
        return self.registration_store.issue(
            account,
            device_id or uuid4(),
            normalized_key,
            normalized_label,
            origin,
            fallback=bool(existing),
            enrollment_method="email",
            issued_at=self._now(),
        )

    async def issue_linking_otp(
        self,
        account_id: UUID,
        issuing_device_id: UUID,
        *,
        network_identifier: str = "unknown",
    ) -> DeviceLinkingOtpResult:
        """Create a short-lived code from an active device."""

        now = self._now()
        account = await self.account_store.get_by_id(account_id)
        device = await self.device_store.get_by_id(account_id, issuing_device_id)
        if (
            account is None
            or device is None
            or device.status != "active"
            or device.epoch != account.device_epoch
        ):
            raise DeviceAuthFailure("device-linking is unavailable")
        if not await self._allow(
            (
                (
                    "device-linking:create:account",
                    str(account_id),
                    10,
                    DEVICE_LINKING_RATE_LIMIT_WINDOW,
                ),
                (
                    "device-linking:create:device",
                    str(issuing_device_id),
                    5,
                    DEVICE_LINKING_RATE_LIMIT_WINDOW,
                ),
            ),
            now=now,
        ):
            await _audit_device_event(
                self._security_event_store,
                "rate_limited",
                "blocked",
                now,
                user_id=account_id,
                device_id=issuing_device_id,
                network_identifier=network_identifier,
                rate_limiter=self._rate_limiter,
                details={"scope": "device_linking_creation"},
            )
            raise DeviceLinkingRateLimited
        code = str(secrets.randbelow(10**DEVICE_LINKING_OTP_LENGTH)).zfill(
            DEVICE_LINKING_OTP_LENGTH
        )
        record = await self.linking_otp_store.create(
            account_id,
            issuing_device_id,
            hashlib.sha256(code.encode("ascii")).digest(),
            now + DEVICE_LINKING_OTP_LIFETIME,
        )
        await _audit_device_event(
            self._security_event_store,
            "device_linking_otp_created",
            "success",
            now,
            user_id=account_id,
            device_id=issuing_device_id,
            network_identifier=network_identifier,
            rate_limiter=self._rate_limiter,
        )
        return DeviceLinkingOtpResult(code, record)

    async def issue_linking_challenge(
        self,
        code: str,
        public_key_spki: bytes,
        label: str,
        origin: str,
        *,
        device_id: UUID | None = None,
        network_identifier: str = "unknown",
    ) -> RegistrationChallenge:
        """Validate a linking code and bind it to a new public key challenge."""

        now = self._now()
        if not isinstance(code, str) or not _DEVICE_LINKING_OTP_RE.fullmatch(code.strip()):
            raise DeviceAuthFailure(DEVICE_LINKING_FAILURE)
        normalized_code = code.strip()
        code_hash = hashlib.sha256(normalized_code.encode("ascii")).digest()
        if not await self._allow(
            (
                (
                    "device-linking:redeem:network",
                    network_identifier,
                    30,
                    DEVICE_LINKING_RATE_LIMIT_WINDOW,
                ),
                (
                    "device-linking:redeem:code",
                    encode_base64url(code_hash),
                    10,
                    DEVICE_LINKING_RATE_LIMIT_WINDOW,
                ),
            ),
            now=now,
        ):
            raise DeviceLinkingRateLimited
        record = await self.linking_otp_store.get_active_by_hash(code_hash)
        if record is None or record.attempt_count >= 10:
            raise DeviceAuthFailure(DEVICE_LINKING_FAILURE)
        account = await self.account_store.get_by_id(record.user_id)
        issuer = await self.device_store.get_by_id(record.user_id, record.issuing_device_id)
        if (
            account is None
            or issuer is None
            or issuer.status != "active"
            or issuer.epoch != account.device_epoch
        ):
            raise DeviceAuthFailure(DEVICE_LINKING_FAILURE)
        try:
            normalized_key = bytes(public_key_spki)
            fingerprint_public_key(normalized_key)
            normalized_label = normalize_device_label(label)
        except (DeviceCryptoError, TypeError, ValueError) as error:
            raise DeviceAuthFailure(DEVICE_LINKING_FAILURE) from error
        return self.registration_store.issue(
            account,
            device_id or uuid4(),
            normalized_key,
            normalized_label,
            origin,
            fallback=False,
            enrollment_method="device_link",
            linking_otp_id=record.id,
            linked_by_device_id=record.issuing_device_id,
            issued_at=now,
        )

    async def complete_registration(
        self,
        challenge_id: UUID,
        signature: bytes,
        *,
        origin: str,
    ) -> DeviceAuthResult:
        """Verify a key proof and finish email fallback or device linking."""

        now = self._now()
        state = self.registration_store.get(challenge_id, now=now)
        if state is None or state.challenge.origin != origin or state.attempts >= 10:
            raise DeviceAuthFailure("registration challenge is invalid")
        if not verify_p1363_signature(
            state.public_key_spki,
            signature,
            signed_message(state.challenge.payload),
        ):
            self.registration_store.mark_failed(challenge_id, now=now)
            if state.challenge.linking_otp_id is not None:
                await self.linking_otp_store.mark_failed(state.challenge.linking_otp_id)
            raise DeviceAuthFailure("registration proof is invalid")
        claimed = self.registration_store.consume(challenge_id, now=now)
        if claimed is None:
            raise DeviceAuthFailure("registration challenge was already used")
        account = await self.account_store.get_by_id(claimed.challenge.account_id)
        if account is None or account.device_epoch != claimed.challenge.epoch:
            raise DeviceAuthFailure("registration account is stale")
        if claimed.challenge.linking_otp_id is not None:
            device = await self.linking_otp_store.consume_and_register(
                claimed.challenge.linking_otp_id,
                account.id,
                cast(UUID, claimed.challenge.linked_by_device_id),
                account.device_epoch,
                claimed.challenge.device_id,
                claimed.label,
                claimed.public_key_spki,
                claimed.challenge.fingerprint,
            )
            if device is None:
                raise DeviceAuthFailure(DEVICE_LINKING_FAILURE)
            fallback = False
            event_type = "device_linked"
        else:
            register = getattr(self.device_store, "register_for_email", None)
            if not callable(register):
                raise DeviceAuthFailure("email fallback is unavailable")
            device = await register(
                account.id,
                account.device_epoch,
                claimed.label,
                claimed.public_key_spki,
                claimed.challenge.fingerprint,
                claimed.challenge.device_id,
            )
            fallback = claimed.challenge.fallback
            event_type = "email_fallback_completed" if fallback else "device_registered"
            if fallback:
                marker = getattr(self.account_store, "mark_email_fallback", None)
                if callable(marker):
                    await marker(account.id, at=now)
        session = await self.session_service.create(
            account.id,
            device.id,
            account.device_epoch,
            created_at=now,
        )
        await _audit_device_event(
            self._security_event_store,
            event_type,
            "success",
            now,
            user_id=account.id,
            device_id=device.id,
        )
        return DeviceAuthResult(account, device, session, fallback)

    async def issue_login_challenge(
        self,
        account_id: UUID,
        device_id: UUID,
        origin: str,
    ) -> DeviceLoginChallenge:
        """Issue a fresh proof challenge for an active returning device."""

        account = await self.account_store.get_by_id(account_id)
        device = await self.device_store.get_by_id(account_id, device_id)
        if (
            account is None
            or device is None
            or device.status != "active"
            or device.epoch != account.device_epoch
        ):
            raise DeviceAuthFailure("device challenge is unavailable")
        nonce = secrets.token_bytes(32)
        challenge = await self.challenge_store.create(
            account_id,
            device_id,
            _hash_nonce(nonce),
            origin,
            self._now() + DEVICE_CHALLENGE_LIFETIME,
        )
        return DeviceLoginChallenge(challenge, account, device, nonce)

    async def complete_login_challenge(
        self,
        account_id: UUID,
        challenge_id: UUID,
        nonce: bytes,
        signature: bytes,
        *,
        origin: str,
    ) -> DeviceAuthResult:
        """Verify and consume one returning-device challenge."""

        current = self._now()
        challenge = await self.challenge_store.get_by_id(account_id, challenge_id)
        if challenge is None or challenge.origin != origin:
            raise DeviceAuthFailure(DEVICE_AUTH_FAILURE)
        account = await self.account_store.get_by_id(account_id)
        device = await self.device_store.get_by_id(account_id, challenge.device_id)
        if (
            account is None
            or device is None
            or device.status != "active"
            or device.epoch != account.device_epoch
            or challenge.expires_at <= current
            or challenge.consumed_at is not None
            or challenge.nonce_hash != _hash_nonce(nonce)
        ):
            await self.challenge_store.mark_failed(account_id, challenge_id)
            raise DeviceAuthFailure(DEVICE_AUTH_FAILURE)
        payload = challenge_payload(challenge, account, device, nonce=nonce)
        if not verify_p1363_signature(
            device.signing_public_key_spki,
            signature,
            signed_message(payload),
        ):
            await self.challenge_store.mark_failed(account_id, challenge_id)
            raise DeviceAuthFailure(DEVICE_AUTH_FAILURE)
        consumed = await self.challenge_store.consume(account_id, challenge_id)
        if consumed is None:
            raise DeviceAuthFailure(DEVICE_AUTH_FAILURE)
        touched = await self.device_store.touch_last_seen(account_id, device.id)
        session = await self.session_service.create(
            account_id,
            device.id,
            account.device_epoch,
            created_at=current,
        )
        return DeviceAuthResult(account, touched or device, session)


def public_device(device: DeviceRecord) -> dict[str, object]:
    """Serialize safe device metadata without exposing public-key bytes."""

    return {
        "device_id": str(device.id),
        "epoch": device.epoch,
        "label": device.label,
        "fingerprint": encode_base64url(device.fingerprint),
        "status": device.status,
        "created_at": device.created_at,
        "last_seen_at": device.last_seen_at,
        "revoked_at": device.revoked_at,
        "linked_by_device_id": (
            None if device.linked_by_device_id is None else str(device.linked_by_device_id)
        ),
    }


def public_auth_result(result: DeviceAuthResult) -> dict[str, object]:
    session = public_session(result.session.record)
    return {
        "authenticated": True,
        "account_id": str(result.account.id),
        "device": public_device(result.device),
        "session": session,
        "csrf_token": result.session.csrf_secret,
        "fallback": result.fallback,
    }


class RegistrationChallengeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    bootstrap_token: str = Field(min_length=1, max_length=512)
    public_key_spki: str | None = Field(default=None, min_length=1, max_length=4096)
    public_key: str | None = Field(default=None, min_length=1, max_length=4096)
    label: str = Field(default="This browser", min_length=1, max_length=MAX_DEVICE_LABEL_LENGTH)
    device_id: UUID | None = None


class RegistrationCompleteRequest(BaseModel):
    challenge_id: UUID
    signature: str = Field(min_length=1, max_length=1024)


class DeviceLinkingChallengeRequest(BaseModel):
    otp: str | None = Field(default=None, min_length=1, max_length=64)
    linking_otp: str | None = Field(default=None, min_length=1, max_length=64)
    public_key_spki: str | None = Field(default=None, min_length=1, max_length=4096)
    public_key: str | None = Field(default=None, min_length=1, max_length=4096)
    label: str = Field(default="This browser", min_length=1, max_length=MAX_DEVICE_LABEL_LENGTH)
    device_id: UUID | None = None


class DeviceChallengeRequest(BaseModel):
    account_id: UUID
    device_id: UUID


class DeviceChallengeCompleteRequest(BaseModel):
    account_id: UUID
    challenge_id: UUID
    nonce: str = Field(min_length=1, max_length=128)
    signature: str = Field(min_length=1, max_length=1024)


class DeviceRenameRequest(BaseModel):
    label: str = Field(min_length=1, max_length=MAX_DEVICE_LABEL_LENGTH)


def _service_from_request(request: Request) -> DeviceAuthService:
    service = getattr(request.app.state, "device_auth_service", None)
    if not isinstance(service, DeviceAuthService):
        raise RuntimeError("device authentication service is not configured")
    return service


def _origin(request: Request) -> str:
    origin = request.headers.get("origin")
    if origin is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Origin not allowed.")
    return origin


def _network_identifier(request: Request) -> str:
    client = request.client
    return "unknown" if client is None or not client.host else client.host


def _decode_signature(value: str) -> bytes:
    return decode_base64url(value, maximum_bytes=512)


def _decode_key(value: str) -> bytes:
    return decode_base64url(value, maximum_bytes=1024)


def _challenge_response(challenge: RegistrationChallenge) -> dict[str, object]:
    return {
        "challenge_id": str(challenge.challenge_id),
        "account_id": str(challenge.account_id),
        "device_id": str(challenge.device_id),
        "device_epoch": challenge.epoch,
        "nonce": encode_base64url(challenge.nonce),
        "origin": challenge.origin,
        "issued_at": challenge.issued_at,
        "expires_at": challenge.expires_at,
        "fingerprint": encode_base64url(challenge.fingerprint),
        "protocol_version": DEVICE_PROTOCOL_VERSION,
        "challenge_version": DEVICE_CHALLENGE_VERSION,
        "fallback": challenge.fallback,
        "enrollment_method": challenge.enrollment_method,
        "payload": challenge.payload,
    }


def _login_challenge_response(challenge: DeviceLoginChallenge) -> dict[str, object]:
    return {
        "challenge_id": str(challenge.challenge.id),
        "account_id": str(challenge.account.id),
        "device_id": str(challenge.device.id),
        "device_epoch": challenge.account.device_epoch,
        "nonce": encode_base64url(challenge.nonce),
        "origin": challenge.challenge.origin,
        "issued_at": challenge.challenge.created_at,
        "expires_at": challenge.challenge.expires_at,
        "protocol_version": DEVICE_PROTOCOL_VERSION,
        "challenge_version": DEVICE_CHALLENGE_VERSION,
        "payload": challenge.payload,
    }


router = APIRouter(prefix="/auth", tags=["devices"])


@router.post("/devices/registration-challenge")
@router.post("/devices/register/challenge")
async def registration_challenge(
    payload: RegistrationChallengeRequest,
    request: Request,
    _origin_check: Annotated[None, Depends(require_exact_origin)],
) -> dict[str, object]:
    try:
        challenge = await _service_from_request(request).issue_registration_challenge(
            payload.bootstrap_token,
            _decode_key(payload.public_key_spki or payload.public_key or ""),
            payload.label,
            _origin(request),
            device_id=payload.device_id,
        )
    except (DeviceAuthError, DeviceCryptoError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=DEVICE_REGISTRATION_FAILURE,
        ) from error
    return _challenge_response(challenge)


@router.post("/devices/registration")
@router.post("/devices/register")
async def complete_registration(
    payload: RegistrationCompleteRequest,
    request: Request,
    response: Response,
    _origin_check: Annotated[None, Depends(require_exact_origin)],
) -> dict[str, object]:
    try:
        result = await _service_from_request(request).complete_registration(
            payload.challenge_id,
            _decode_signature(payload.signature),
            origin=_origin(request),
        )
    except (DeviceAuthError, DeviceCryptoError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=DEVICE_AUTH_FAILURE,
        ) from error
    set_session_cookie(response, result.session.token)
    return public_auth_result(result)


@router.post("/devices/linking-otp")
@router.post("/devices/link/otp")
async def create_linking_otp(
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    try:
        result = await _service_from_request(request).issue_linking_otp(
            session.user_id,
            session.device_id,
            network_identifier=_network_identifier(request),
        )
    except DeviceLinkingRateLimited as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=RATE_LIMIT_MESSAGE
        ) from error
    except (DeviceAuthError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=DEVICE_LINKING_FAILURE
        ) from error
    return {
        "message": DEVICE_LINKING_OTP_MESSAGE,
        "otp": result.code,
        "expires_at": result.record.expires_at,
    }


@router.post("/devices/linking-challenge")
@router.post("/devices/link/challenge")
async def linking_challenge(
    payload: DeviceLinkingChallengeRequest,
    request: Request,
    _origin_check: Annotated[None, Depends(require_exact_origin)],
) -> dict[str, object]:
    try:
        challenge = await _service_from_request(request).issue_linking_challenge(
            payload.otp or payload.linking_otp or "",
            _decode_key(payload.public_key_spki or payload.public_key or ""),
            payload.label,
            _origin(request),
            device_id=payload.device_id,
            network_identifier=_network_identifier(request),
        )
    except DeviceLinkingRateLimited as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=RATE_LIMIT_MESSAGE
        ) from error
    except (DeviceAuthError, DeviceCryptoError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=DEVICE_LINKING_FAILURE
        ) from error
    return _challenge_response(challenge)


@router.post("/devices/linking")
@router.post("/devices/link/complete")
async def complete_linking(
    payload: RegistrationCompleteRequest,
    request: Request,
    response: Response,
    _origin_check: Annotated[None, Depends(require_exact_origin)],
) -> dict[str, object]:
    try:
        result = await _service_from_request(request).complete_registration(
            payload.challenge_id,
            _decode_signature(payload.signature),
            origin=_origin(request),
        )
    except (DeviceAuthError, DeviceCryptoError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=DEVICE_LINKING_FAILURE
        ) from error
    set_session_cookie(response, result.session.token)
    return public_auth_result(result)


@router.post("/devices/challenge")
@router.post("/device-challenge")
@router.post("/devices/login/challenge")
async def issue_login_challenge(
    payload: DeviceChallengeRequest,
    request: Request,
    _origin_check: Annotated[None, Depends(require_exact_origin)],
) -> dict[str, object]:
    try:
        challenge = await _service_from_request(request).issue_login_challenge(
            payload.account_id,
            payload.device_id,
            _origin(request),
        )
    except (DeviceAuthError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=DEVICE_AUTH_FAILURE
        ) from error
    return _login_challenge_response(challenge)


@router.post("/devices/challenge/verify")
@router.post("/device-challenge/verify")
@router.post("/devices/login")
async def complete_login_challenge(
    payload: DeviceChallengeCompleteRequest,
    request: Request,
    response: Response,
    _origin_check: Annotated[None, Depends(require_exact_origin)],
) -> dict[str, object]:
    try:
        result = await _service_from_request(request).complete_login_challenge(
            payload.account_id,
            payload.challenge_id,
            decode_base64url(payload.nonce, maximum_bytes=64),
            _decode_signature(payload.signature),
            origin=_origin(request),
        )
    except (DeviceAuthError, DeviceCryptoError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=DEVICE_AUTH_FAILURE
        ) from error
    set_session_cookie(response, result.session.token)
    return public_auth_result(result)


@router.get("/devices")
async def list_devices(
    request: Request,
    session: Annotated[SessionRecord, Depends(get_authenticated_session)],
) -> dict[str, object]:
    check_optional_origin(request)
    records = await _service_from_request(request).device_store.list_for_account(session.user_id)
    return {"devices": [public_device(device) for device in records]}


@router.patch("/devices/{device_id}")
async def rename_device(
    device_id: UUID,
    payload: DeviceRenameRequest,
    request: Request,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    try:
        device = await _service_from_request(request).device_store.rename(
            session.user_id,
            device_id,
            normalize_device_label(payload.label),
        )
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=DEVICE_AUTH_FAILURE)
    return {"device": public_device(device)}


@router.delete("/devices/{device_id}")
async def logout_device(
    device_id: UUID,
    request: Request,
    response: Response,
    session: Annotated[SessionRecord, Depends(require_session_csrf)],
) -> dict[str, object]:
    device = await _service_from_request(request).device_store.logout_with_sessions(
        session.user_id,
        device_id,
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=DEVICE_AUTH_FAILURE)
    presence_manager = getattr(request.app.state, "presence_manager", None)
    if presence_manager is not None:
        disconnect = getattr(presence_manager, "disconnect_device", None)
        if callable(disconnect):
            await disconnect(session.user_id, device_id)
    if device_id == session.device_id:
        from .session_api import clear_session_cookie

        clear_session_cookie(response)
    return {"device": public_device(device), "logged_out": True}


__all__ = [
    "DEVICE_AUTH_FAILURE",
    "DEVICE_CHALLENGE_LIFETIME",
    "DEVICE_LINKING_FAILURE",
    "DEVICE_LINKING_OTP_LIFETIME",
    "DeviceAuthError",
    "DeviceAuthFailure",
    "DeviceAuthResult",
    "DeviceAuthService",
    "DeviceChallengeCompleteRequest",
    "DeviceChallengeRequest",
    "DeviceLinkingOtpResult",
    "DeviceLoginChallenge",
    "DeviceRenameRequest",
    "RegistrationChallenge",
    "RegistrationChallengeRequest",
    "RegistrationChallengeStore",
    "RegistrationCompleteRequest",
    "normalize_device_label",
    "public_auth_result",
    "public_device",
    "router",
]
