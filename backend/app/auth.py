"""Email OTP bootstrap flow and the temporary pre-device state it produces."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import unicodedata
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Annotated, Protocol, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .adapters import AuthGateway, InvalidOtpError
from .repositories.accounts import AccountRepository
from .repositories.models import AccountRecord
from .repositories.rate_limits import PersistentRateLimiter
from .security import check_optional_origin
from .sessions import hash_secret, new_opaque_token

OTP_WINDOW = timedelta(minutes=10)
OTP_START_EMAIL_LIMIT = 3
OTP_START_NETWORK_LIMIT = 10
OTP_VERIFY_EMAIL_LIMIT = 5
OTP_VERIFY_NETWORK_LIMIT = 20
BOOTSTRAP_LIFETIME = timedelta(minutes=10)

OTP_SENT_MESSAGE = "If the email can receive messages, a one-time code has been sent."
INVALID_OTP_MESSAGE = "The email or one-time code is invalid."
RATE_LIMIT_MESSAGE = "Too many attempts. Try again later."


def normalize_email(value: str) -> str:
    """Normalize an email for lookup without applying provider-specific aliases."""

    if not isinstance(value, str):
        raise ValueError("email must be text")
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    if not 3 <= len(normalized) <= 320:
        raise ValueError("email must be between 3 and 320 characters")
    if any(character.isspace() or ord(character) < 32 for character in normalized):
        raise ValueError("email must not contain whitespace or controls")
    if normalized.count("@") != 1:
        raise ValueError("email must contain one at-sign")
    local_part, domain = normalized.rsplit("@", 1)
    if not local_part or not domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("email must contain a valid local part and domain")
    if ".." in local_part or ".." in domain:
        raise ValueError("email must not contain empty labels")
    if "." not in domain:
        raise ValueError("email domain must contain a dot")
    if any(character in normalized for character in '()<>[],;:\\"'):
        raise ValueError("email contains unsupported characters")
    return normalized


def network_fingerprint(network_identifier: str, secret: bytes) -> bytes:
    """Return an HMAC fingerprint for a network identifier without storing it raw."""

    if not secret:
        raise ValueError("network fingerprint secret must not be empty")
    normalized = network_identifier.strip().casefold() or "unknown"
    return hmac.new(secret, normalized.encode("utf-8"), hashlib.sha256).digest()


class RateLimiter:
    """Small process-local limiter keyed only by HMAC fingerprints."""

    def __init__(self, secret: bytes | None = None) -> None:
        self._secret = secrets.token_bytes(32) if secret is None else bytes(secret)
        if not self._secret:
            raise ValueError("rate-limit secret must not be empty")
        self._buckets: dict[tuple[str, bytes], tuple[datetime, int]] = {}
        self._lock = threading.Lock()

    @property
    def secret(self) -> bytes:
        """Return the process secret for deriving stable fingerprints in one instance."""

        return self._secret

    def fingerprint(self, scope: str, value: str) -> bytes:
        """Derive a scope-separated HMAC bucket key."""

        return hmac.new(
            self._secret,
            f"{scope}:{value}".encode(),
            hashlib.sha256,
        ).digest()

    def allow(
        self,
        scope: str,
        value: str,
        limit: int,
        window: timedelta,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Atomically consume one request when a bucket has capacity."""

        if not scope or limit <= 0 or window <= timedelta(0):
            raise ValueError("rate-limit scope, limit, and window must be valid")
        current = datetime.now(UTC) if now is None else now
        if current.tzinfo is None:
            raise ValueError("rate-limit timestamps must be timezone-aware")
        current = current.astimezone(UTC)
        bucket_key = (scope, self.fingerprint(scope, value))
        with self._lock:
            expires_at, request_count = self._buckets.get(bucket_key, (current, 0))
            if expires_at <= current:
                expires_at = current + window
                request_count = 0
            if request_count >= limit:
                self._buckets[bucket_key] = (expires_at, request_count)
                return False
            self._buckets[bucket_key] = (expires_at, request_count + 1)
            return True

    def allow_many(
        self,
        requests: Sequence[tuple[str, str, int, timedelta]],
        *,
        now: datetime | None = None,
    ) -> bool:
        """Consume several buckets together, leaving all untouched on rejection."""

        if not requests:
            raise ValueError("at least one rate-limit bucket is required")
        current = datetime.now(UTC) if now is None else now
        if current.tzinfo is None:
            raise ValueError("rate-limit timestamps must be timezone-aware")
        current = current.astimezone(UTC)
        bucket_keys: list[tuple[str, bytes, int, timedelta]] = []
        for scope, value, limit, window in requests:
            if not scope or limit <= 0 or window <= timedelta(0):
                raise ValueError("rate-limit scope, limit, and window must be valid")
            bucket_keys.append((scope, self.fingerprint(scope, value), limit, window))
        with self._lock:
            states: list[tuple[tuple[str, bytes], datetime, int, timedelta]] = []
            for scope, bucket_key, limit, window in bucket_keys:
                expires_at, request_count = self._buckets.get((scope, bucket_key), (current, 0))
                if expires_at <= current:
                    expires_at = current + window
                    request_count = 0
                if request_count >= limit:
                    return False
                states.append(((scope, bucket_key), expires_at, request_count, window))
            for composite_key, expires_at, request_count, _ in states:
                self._buckets[composite_key] = (expires_at, request_count + 1)
        return True

    def allow_fingerprint(
        self,
        scope: str,
        fingerprint: bytes,
        limit: int,
        window: timedelta,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Consume a bucket when the caller already has a SHA-256 fingerprint."""

        if len(fingerprint) != hashlib.sha256().digest_size:
            raise ValueError("rate-limit fingerprints must be SHA-256 digests")
        if not scope or limit <= 0 or window <= timedelta(0):
            raise ValueError("rate-limit scope, limit, and window must be valid")
        current = datetime.now(UTC) if now is None else now
        if current.tzinfo is None:
            raise ValueError("rate-limit timestamps must be timezone-aware")
        current = current.astimezone(UTC)
        bucket_key = (scope, bytes(fingerprint))
        with self._lock:
            expires_at, request_count = self._buckets.get(bucket_key, (current, 0))
            if expires_at <= current:
                expires_at = current + window
                request_count = 0
            if request_count >= limit:
                self._buckets[bucket_key] = (expires_at, request_count)
                return False
            self._buckets[bucket_key] = (expires_at, request_count + 1)
            return True


RateLimiterPort = RateLimiter | PersistentRateLimiter


class AccountStore(Protocol):
    """Account lookup/create boundary used after a verified OTP."""

    async def get_or_create(
        self,
        supabase_user_id: UUID,
        email_normalized: str,
        *,
        created_at: datetime,
    ) -> AccountRecord: ...

    async def get_by_id(self, account_id: UUID) -> AccountRecord | None: ...

    async def get_by_email(self, email_normalized: str) -> AccountRecord | None: ...

    async def mark_email_fallback(
        self,
        account_id: UUID,
        at: datetime,
    ) -> AccountRecord | None: ...


class RepositoryAccountStore:
    """Account store backed by the private application schema."""

    def __init__(self, repository: AccountRepository) -> None:
        self._repository = repository

    async def get_or_create(
        self,
        supabase_user_id: UUID,
        email_normalized: str,
        *,
        created_at: datetime,
    ) -> AccountRecord:
        account = await self._repository.get_by_supabase_user_id(supabase_user_id)
        if account is not None:
            if account.email_normalized != email_normalized:
                raise ValueError("verified identity email does not match account")
            return account

        existing = await self._repository.get_by_email(email_normalized)
        if existing is not None:
            if existing.supabase_user_id != supabase_user_id:
                raise ValueError("email is linked to another identity")
            return existing
        return await self._repository.create(supabase_user_id, email_normalized)

    async def get_by_id(self, account_id: UUID) -> AccountRecord | None:
        return await self._repository.get_by_id(account_id)

    async def get_by_email(self, email_normalized: str) -> AccountRecord | None:
        return await self._repository.get_by_email(email_normalized)

    async def mark_email_fallback(
        self,
        account_id: UUID,
        at: datetime,
    ) -> AccountRecord | None:
        return await self._repository.mark_email_fallback(account_id, at)


class InMemoryAccountStore:
    """Explicitly non-production account store for deterministic integration tests."""

    def __init__(self) -> None:
        self._by_identity: dict[UUID, AccountRecord] = {}
        self._by_email: dict[str, AccountRecord] = {}
        self._lock = threading.Lock()

    async def get_or_create(
        self,
        supabase_user_id: UUID,
        email_normalized: str,
        *,
        created_at: datetime,
    ) -> AccountRecord:
        current = created_at.astimezone(UTC)
        with self._lock:
            account = self._by_identity.get(supabase_user_id)
            if account is not None:
                if account.email_normalized != email_normalized:
                    raise ValueError("verified identity email does not match account")
                return account
            existing = self._by_email.get(email_normalized)
            if existing is not None:
                if existing.supabase_user_id != supabase_user_id:
                    raise ValueError("email is linked to another identity")
                return existing
            account = AccountRecord(
                id=uuid4(),
                supabase_user_id=supabase_user_id,
                email_normalized=email_normalized,
                device_epoch=0,
                created_at=current,
                email_fallback_at=None,
                deleted_at=None,
            )
            self._by_identity[supabase_user_id] = account
            self._by_email[email_normalized] = account
            return account

    async def get_by_id(self, account_id: UUID) -> AccountRecord | None:
        with self._lock:
            return next(
                (account for account in self._by_identity.values() if account.id == account_id),
                None,
            )

    async def get_by_email(self, email_normalized: str) -> AccountRecord | None:
        with self._lock:
            account = self._by_email.get(email_normalized)
            return None if account is None or account.deleted_at is not None else account

    async def mark_email_fallback(
        self,
        account_id: UUID,
        at: datetime,
    ) -> AccountRecord | None:
        current = at.astimezone(UTC)
        with self._lock:
            account = next(
                (item for item in self._by_identity.values() if item.id == account_id),
                None,
            )
            if account is None or account.deleted_at is not None:
                return None
            updated = replace(account, email_fallback_at=current)
            self._by_identity[account.supabase_user_id] = updated
            self._by_email[account.email_normalized] = updated
            return updated


@dataclass(frozen=True, slots=True)
class BootstrapCredentials:
    """Short-lived state for the next device-registration step."""

    bootstrap_id: UUID
    token: str
    account_id: UUID
    email_normalized: str
    device_epoch: int
    expires_at: datetime

    @property
    def bootstrap_token(self) -> str:
        """Name used by the HTTP response for the opaque bootstrap value."""

        return self.token


@dataclass(frozen=True, slots=True)
class _BootstrapState:
    bootstrap_id: UUID
    token_hash: bytes
    account_id: UUID
    email_normalized: str
    device_epoch: int
    expires_at: datetime


class BootstrapStateStore:
    """In-memory, one-time bootstrap state; it is intentionally not durable."""

    def __init__(self, lifetime: timedelta = BOOTSTRAP_LIFETIME) -> None:
        if lifetime <= timedelta(0):
            raise ValueError("bootstrap lifetime must be positive")
        self._lifetime = lifetime
        self._states: dict[bytes, _BootstrapState] = {}
        self._lock = threading.Lock()

    def issue(
        self,
        account: AccountRecord,
        *,
        issued_at: datetime,
    ) -> BootstrapCredentials:
        current = issued_at.astimezone(UTC)
        token = new_opaque_token()
        state = _BootstrapState(
            bootstrap_id=uuid4(),
            token_hash=hash_secret(token),
            account_id=account.id,
            email_normalized=account.email_normalized,
            device_epoch=account.device_epoch,
            expires_at=current + self._lifetime,
        )
        with self._lock:
            self._states[state.token_hash] = state
        return BootstrapCredentials(
            bootstrap_id=state.bootstrap_id,
            token=token,
            account_id=state.account_id,
            email_normalized=state.email_normalized,
            device_epoch=state.device_epoch,
            expires_at=state.expires_at,
        )

    def consume(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> BootstrapCredentials | None:
        """Consume a valid bootstrap value exactly once."""

        current = datetime.now(UTC) if now is None else now
        current = current.astimezone(UTC)
        token_hash = hash_secret(token)
        with self._lock:
            state = self._states.pop(token_hash, None)
        if state is None or state.expires_at <= current:
            return None
        return BootstrapCredentials(
            bootstrap_id=state.bootstrap_id,
            token=token,
            account_id=state.account_id,
            email_normalized=state.email_normalized,
            device_epoch=state.device_epoch,
            expires_at=state.expires_at,
        )

    def peek(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> BootstrapCredentials | None:
        """Read valid bootstrap metadata without consuming the one-time value."""

        current = datetime.now(UTC) if now is None else now
        if current.tzinfo is None:
            raise ValueError("bootstrap timestamps must be timezone-aware")
        current = current.astimezone(UTC)
        token_hash = hash_secret(token)
        with self._lock:
            state = self._states.get(token_hash)
        if state is None or state.expires_at <= current:
            return None
        return BootstrapCredentials(
            bootstrap_id=state.bootstrap_id,
            token=token,
            account_id=state.account_id,
            email_normalized=state.email_normalized,
            device_epoch=state.device_epoch,
            expires_at=state.expires_at,
        )


class OtpRateLimitedError(RuntimeError):
    """Raised before an AuthGateway call when an OTP bucket is exhausted."""


class OtpInvalidError(ValueError):
    """Raised when a provider identity cannot be safely accepted."""


class OtpBootstrapService:
    """Coordinate rate limits, AuthGateway verification, account state, and bootstrap."""

    def __init__(
        self,
        gateway: AuthGateway,
        account_store: AccountStore,
        *,
        bootstrap_store: BootstrapStateStore | None = None,
        rate_limiter: RateLimiterPort | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.gateway = gateway
        self.account_store = account_store
        self.bootstrap_store = bootstrap_store or BootstrapStateStore()
        self.rate_limiter = rate_limiter or RateLimiter()
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        current = self._clock()
        if current.tzinfo is None:
            raise ValueError("authentication timestamps must be timezone-aware")
        return current.astimezone(UTC)

    async def _allow(
        self,
        email_normalized: str,
        network_identifier: str,
        *,
        verify: bool,
    ) -> bool:
        email_limit = OTP_VERIFY_EMAIL_LIMIT if verify else OTP_START_EMAIL_LIMIT
        network_limit = OTP_VERIFY_NETWORK_LIMIT if verify else OTP_START_NETWORK_LIMIT
        email_scope = "otp:verify:email" if verify else "otp:start:email"
        network_scope = "otp:verify:network" if verify else "otp:start:network"
        current = self._now()
        result = self.rate_limiter.allow_many(
            (
                (email_scope, email_normalized, email_limit, OTP_WINDOW),
                (network_scope, network_identifier, network_limit, OTP_WINDOW),
            ),
            now=current,
        )
        if isinstance(result, bool):
            return result
        return await cast(Awaitable[bool], result)

    async def start_otp(
        self,
        email: str,
        network_identifier: str,
        *,
        gateway: AuthGateway | None = None,
    ) -> str:
        """Normalize and rate-limit an OTP request before invoking the provider."""

        normalized = normalize_email(email)
        if not await self._allow(normalized, network_identifier, verify=False):
            raise OtpRateLimitedError
        await (gateway or self.gateway).start_otp(normalized)
        return normalized

    async def verify_otp(
        self,
        email: str,
        otp: str,
        network_identifier: str,
        *,
        gateway: AuthGateway | None = None,
    ) -> BootstrapCredentials:
        """Verify an OTP and return non-durable device-bootstrap state."""

        normalized = normalize_email(email)
        if not isinstance(otp, str) or not 1 <= len(otp.strip()) <= 64:
            raise OtpInvalidError
        if not await self._allow(normalized, network_identifier, verify=True):
            raise OtpRateLimitedError
        try:
            identity = await (gateway or self.gateway).verify_otp(normalized, otp.strip())
            identity_id = UUID(identity.user_id)
            identity_email = normalize_email(identity.email)
            if identity_email != normalized:
                raise OtpInvalidError
        except (InvalidOtpError, ValueError, TypeError) as error:
            raise OtpInvalidError from error
        verified_at = self._now()
        account = await self.account_store.get_or_create(
            identity_id,
            normalized,
            created_at=verified_at,
        )
        return self.bootstrap_store.issue(account, issued_at=verified_at)

    def consume_bootstrap(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> BootstrapCredentials | None:
        """Expose one-time consumption for the later device-registration service."""

        return self.bootstrap_store.consume(token, now=now)

    def peek_bootstrap(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> BootstrapCredentials | None:
        """Inspect bootstrap metadata while leaving it available for registration."""

        return self.bootstrap_store.peek(token, now=now)


class OtpStartRequest(BaseModel):
    """JSON body for the generic OTP-start endpoint."""

    email: str = Field(min_length=1, max_length=320)


class OtpVerifyRequest(BaseModel):
    """JSON body for the OTP verification endpoint."""

    email: str = Field(min_length=1, max_length=320)
    otp: str = Field(min_length=1, max_length=64)


def _network_identifier(request: Request) -> str:
    client = request.client
    return "unknown" if client is None or not client.host else client.host


def _service_from_request(request: Request) -> OtpBootstrapService:
    service = getattr(request.app.state, "otp_service", None)
    if isinstance(service, OtpBootstrapService):
        return service
    settings = getattr(request.app.state, "settings", None)
    if settings is not None and getattr(settings, "app_env", None) != "test":
        raise RuntimeError("production authentication service is not configured")
    gateway = getattr(request.app.state, "auth_gateway", None)
    if gateway is None:
        raise RuntimeError("authentication service is not configured")
    service = OtpBootstrapService(gateway, InMemoryAccountStore())
    request.app.state.otp_service = service
    return service


get_auth_service = _service_from_request


def get_auth_gateway(request: Request) -> AuthGateway:
    """FastAPI dependency that makes the configured gateway replaceable in tests."""

    gateway = getattr(request.app.state, "auth_gateway", None)
    if gateway is None:
        raise RuntimeError("authentication gateway is not configured")
    return cast(AuthGateway, gateway)


router = APIRouter(prefix="/auth/otp", tags=["authentication"])


@router.post("/start", status_code=status.HTTP_202_ACCEPTED)
async def start_otp(
    payload: OtpStartRequest,
    request: Request,
    service: Annotated[OtpBootstrapService, Depends(_service_from_request)],
    gateway: Annotated[AuthGateway, Depends(get_auth_gateway)],
) -> dict[str, str]:
    """Start a generic email OTP flow without revealing account existence."""

    check_optional_origin(request)
    try:
        await service.start_otp(payload.email, _network_identifier(request), gateway=gateway)
    except OtpRateLimitedError as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=RATE_LIMIT_MESSAGE,
        ) from error
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enter a valid email address.",
        ) from error
    return {"message": OTP_SENT_MESSAGE}


@router.post("/verify")
async def verify_otp(
    payload: OtpVerifyRequest,
    request: Request,
    service: Annotated[OtpBootstrapService, Depends(_service_from_request)],
    gateway: Annotated[AuthGateway, Depends(get_auth_gateway)],
) -> dict[str, object]:
    """Verify an OTP and return only short-lived pre-device bootstrap state."""

    check_optional_origin(request)
    try:
        bootstrap = await service.verify_otp(
            payload.email,
            payload.otp,
            _network_identifier(request),
            gateway=gateway,
        )
    except OtpRateLimitedError as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=RATE_LIMIT_MESSAGE,
        ) from error
    except (OtpInvalidError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_OTP_MESSAGE,
        ) from error
    return {
        "bootstrap_id": str(bootstrap.bootstrap_id),
        "bootstrap_token": bootstrap.token,
        "account_id": str(bootstrap.account_id),
        "device_epoch": bootstrap.device_epoch,
        "expires_at": bootstrap.expires_at,
    }


auth_router = router
