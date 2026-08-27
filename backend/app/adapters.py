"""Typed service ports and deterministic adapters used by tests."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol

from app.config import AppEnvironment, ConfigurationError


@dataclass(frozen=True, slots=True)
class AuthIdentity:
    """Identity returned after an email OTP has been verified."""

    user_id: str
    email: str


class AuthGateway(Protocol):
    """Provider boundary for starting and verifying email OTPs."""

    async def start_otp(self, email: str) -> None:
        """Ask the provider to send an OTP to ``email``."""

    async def verify_otp(self, email: str, otp: str) -> AuthIdentity:
        """Verify an OTP and return the provider's authenticated identity."""


@dataclass(frozen=True, slots=True)
class TurnCredentialRequest:
    """Context used to scope one short-lived TURN credential request."""

    account_id: str
    device_id: str
    transfer_id: str
    ttl_seconds: int


@dataclass(frozen=True, slots=True)
class TurnCredentials:
    """ICE server credentials returned by a TURN provider."""

    urls: tuple[str, ...]
    username: str
    credential: str
    expires_at: int


class TurnCredentialProvider(Protocol):
    """Provider boundary for issuing short-lived TURN credentials."""

    async def issue_credentials(self, request: TurnCredentialRequest) -> TurnCredentials:
        """Issue credentials for one authorized transfer context."""


def _require_test_environment(app_env: AppEnvironment) -> None:
    if app_env != "test":
        raise ConfigurationError("fake adapters are only available in the test environment")


def _deterministic_otp(email: str) -> str:
    digest = hashlib.sha256(f"otp:{email}".encode()).digest()
    return f"{int.from_bytes(digest[:4], byteorder='big') % 1_000_000:06d}"


def _deterministic_user_id(email: str) -> str:
    return hashlib.sha256(f"user:{email}".encode()).hexdigest()[:32]


class InvalidOtpError(ValueError):
    """Raised when a fake OTP is missing, incorrect, or already consumed."""


class FakeAuthGateway:
    """Deterministic in-memory AuthGateway for test configuration."""

    def __init__(self, *, app_env: AppEnvironment = "test") -> None:
        _require_test_environment(app_env)
        self._otps: dict[str, str] = {}
        self._requested_emails: list[str] = []

    @property
    def requested_emails(self) -> tuple[str, ...]:
        """Return the emails for which the fake has started OTP delivery."""

        return tuple(self._requested_emails)

    def otp_for(self, email: str) -> str:
        """Return the currently issued OTP for ``email`` in tests."""

        try:
            return self._otps[email]
        except KeyError as error:
            raise InvalidOtpError("no OTP is pending for this email") from error

    async def start_otp(self, email: str) -> None:
        self._otps[email] = _deterministic_otp(email)
        self._requested_emails.append(email)

    async def verify_otp(self, email: str, otp: str) -> AuthIdentity:
        expected = self._otps.get(email)
        if expected is None or not hmac.compare_digest(expected, otp):
            raise InvalidOtpError("invalid OTP")
        del self._otps[email]
        return AuthIdentity(user_id=_deterministic_user_id(email), email=email)


_FAKE_EPOCH_MS = 1_700_000_000_000
_FAKE_TURN_URLS = (
    "stun:turn.test.invalid",
    "turn:turn.test.invalid?transport=udp",
)


class FakeTurnCredentialProvider:
    """Deterministic in-memory TurnCredentialProvider for test configuration."""

    def __init__(self, *, app_env: AppEnvironment = "test") -> None:
        _require_test_environment(app_env)
        self._requests: list[TurnCredentialRequest] = []

    @property
    def requests(self) -> tuple[TurnCredentialRequest, ...]:
        """Return the credential requests received by the fake."""

        return tuple(self._requests)

    async def issue_credentials(self, request: TurnCredentialRequest) -> TurnCredentials:
        if request.ttl_seconds <= 0:
            raise ValueError("TURN credential TTL must be positive")
        self._requests.append(request)
        scope = ":".join((request.account_id, request.device_id, request.transfer_id))
        digest = hashlib.sha256(f"turn:{scope}".encode()).hexdigest()
        return TurnCredentials(
            urls=_FAKE_TURN_URLS,
            username=f"test-{digest[:16]}",
            credential=digest[16:48],
            expires_at=_FAKE_EPOCH_MS + request.ttl_seconds * 1_000,
        )
