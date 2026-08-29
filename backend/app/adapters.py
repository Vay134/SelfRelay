"""Typed service ports and deterministic adapters used by tests."""

from __future__ import annotations

import hashlib
import hmac
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote, urlsplit

import httpx

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


class AuthGatewayUnavailableError(RuntimeError):
    """Raised when an authentication provider cannot safely complete a request."""


class SupabaseAuthGateway:
    """Use Supabase Auth email OTP endpoints without retaining provider sessions."""

    def __init__(self, *, url: str, publishable_key: str) -> None:
        self._url = url.rstrip("/")
        self._headers = {"Accept": "application/json", "apikey": publishable_key}

    async def start_otp(self, email: str) -> None:
        await self._post("/auth/v1/otp", {"email": email, "create_user": True})

    async def verify_otp(self, email: str, otp: str) -> AuthIdentity:
        response = await self._post(
            "/auth/v1/verify", {"email": email, "token": otp, "type": "email"}, invalid_is_otp=True
        )
        try:
            user = response.json()["user"]
            user_id, user_email = user["id"], user["email"]
        except (KeyError, TypeError, ValueError) as error:
            raise AuthGatewayUnavailableError(
                "Supabase Auth returned an invalid response"
            ) from error
        if not isinstance(user_id, str) or not isinstance(user_email, str):
            raise AuthGatewayUnavailableError("Supabase Auth returned an invalid response")
        return AuthIdentity(user_id=user_id, email=user_email)

    async def _post(
        self, path: str, payload: dict[str, object], *, invalid_is_otp: bool = False
    ) -> httpx.Response:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    f"{self._url}{path}", headers=self._headers, json=payload
                )
        except httpx.HTTPError as error:
            raise AuthGatewayUnavailableError("Supabase Auth request failed") from error
        if response.is_success:
            return response
        if invalid_is_otp and 400 <= response.status_code < 500:
            raise InvalidOtpError("invalid OTP")
        raise AuthGatewayUnavailableError("Supabase Auth request failed")


def create_auth_gateway(
    app_env: AppEnvironment,
    adapter: str,
    *,
    supabase_url: str | None = None,
    supabase_publishable_key: str | None = None,
) -> AuthGateway:
    """Build the configured AuthGateway without silently substituting a fake in production."""

    if adapter == "fake":
        return FakeAuthGateway(app_env=app_env)
    if adapter == "supabase" and supabase_url and supabase_publishable_key:
        return SupabaseAuthGateway(url=supabase_url, publishable_key=supabase_publishable_key)
    raise ConfigurationError("Supabase Auth settings must be configured before startup")


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


class TurnCredentialProviderError(RuntimeError):
    """Raised when a TURN provider cannot issue usable credentials."""


class DisabledTurnCredentialProvider:
    """Fail closed when production TURN usage is intentionally disabled."""

    async def issue_credentials(self, request: TurnCredentialRequest) -> TurnCredentials:
        del request
        raise TurnCredentialProviderError("TURN is disabled")


_CLOUDFLARE_TURN_CREDENTIALS_URL = (
    "https://rtc.live.cloudflare.com/v1/turn/keys/{key_id}/credentials/generate-ice-servers"
)
_CLOUDFLARE_MAX_TTL_SECONDS = 48 * 60 * 60


def _required_turn_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{name} must be configured")
    normalized = value.strip()
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized):
        raise ConfigurationError(f"{name} must contain printable characters")
    return normalized


def _turn_scope_identifier(request: TurnCredentialRequest) -> str:
    scope = "\x00".join((request.account_id, request.device_id, request.transfer_id))
    return hashlib.sha256(f"turn:{scope}".encode()).hexdigest()


def _validate_turn_request(request: TurnCredentialRequest) -> None:
    for name in ("account_id", "device_id", "transfer_id"):
        value = getattr(request, name, None)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"TURN credential {name} must not be empty")
    if (
        not isinstance(request.ttl_seconds, int)
        or isinstance(request.ttl_seconds, bool)
        or request.ttl_seconds <= 0
    ):
        raise ValueError("TURN credential TTL must be positive")
    if request.ttl_seconds > _CLOUDFLARE_MAX_TTL_SECONDS:
        raise ValueError("TURN credential TTL exceeds Cloudflare's 48 hour maximum")


def _ice_urls(value: object) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        values = value
    else:
        raise TurnCredentialProviderError("Cloudflare returned invalid ICE server URLs")

    normalized: list[str] = []
    for url in values:
        if not url.strip():
            raise TurnCredentialProviderError("Cloudflare returned an empty ICE server URL")
        try:
            scheme = urlsplit(url).scheme.casefold()
        except ValueError as error:
            raise TurnCredentialProviderError(
                "Cloudflare returned an invalid ICE server URL"
            ) from error
        if scheme not in {"stun", "turn", "turns"}:
            raise TurnCredentialProviderError("Cloudflare returned an unsupported ICE server URL")
        normalized.append(url)
    if not normalized:
        raise TurnCredentialProviderError("Cloudflare returned no ICE server URLs")
    return normalized


def _parse_cloudflare_credentials(payload: object) -> tuple[tuple[str, ...], str, str]:
    if not isinstance(payload, Mapping):
        raise TurnCredentialProviderError("Cloudflare returned an invalid TURN response")
    raw_servers = payload.get("iceServers")
    if not isinstance(raw_servers, list) or not raw_servers:
        raise TurnCredentialProviderError("Cloudflare returned no TURN servers")

    urls: list[str] = []
    username: str | None = None
    credential: str | None = None
    has_turn_url = False
    for raw_server in raw_servers:
        if not isinstance(raw_server, Mapping):
            raise TurnCredentialProviderError("Cloudflare returned an invalid TURN server")
        server_urls = _ice_urls(raw_server.get("urls"))
        for url in server_urls:
            if url not in urls:
                urls.append(url)
            try:
                has_turn_url = has_turn_url or urlsplit(url).scheme.casefold() in {"turn", "turns"}
            except ValueError as error:
                raise TurnCredentialProviderError(
                    "Cloudflare returned an invalid ICE server URL"
                ) from error

        raw_username = raw_server.get("username")
        raw_credential = raw_server.get("credential")
        if raw_username is None and raw_credential is None:
            continue
        if (
            not isinstance(raw_username, str)
            or not raw_username
            or not isinstance(raw_credential, str)
            or not raw_credential
        ):
            raise TurnCredentialProviderError("Cloudflare returned incomplete TURN credentials")
        if username is not None and username != raw_username:
            raise TurnCredentialProviderError("Cloudflare returned conflicting TURN credentials")
        if credential is not None and credential != raw_credential:
            raise TurnCredentialProviderError("Cloudflare returned conflicting TURN credentials")
        username = raw_username
        credential = raw_credential

    if not urls or not has_turn_url or username is None or credential is None:
        raise TurnCredentialProviderError("Cloudflare returned incomplete TURN credentials")
    return tuple(urls), username, credential


class CloudflareTurnCredentialProvider:
    """Issue short-lived ICE credentials using Cloudflare Realtime TURN."""

    def __init__(
        self,
        *,
        turn_key_id: str,
        api_token: str,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 5.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._turn_key_id = _required_turn_text(turn_key_id, "CLOUDFLARE_TURN_KEY_ID")
        self._api_token = _required_turn_text(api_token, "CLOUDFLARE_TURN_API_TOKEN")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ConfigurationError("Cloudflare TURN timeout must be positive")
        self._timeout_seconds = timeout_seconds
        self._client = client
        self._clock = clock

    async def issue_credentials(self, request: TurnCredentialRequest) -> TurnCredentials:
        _validate_turn_request(request)
        url = _CLOUDFLARE_TURN_CREDENTIALS_URL.format(
            key_id=quote(self._turn_key_id, safe=""),
        )
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
        }
        payload = {
            "ttl": request.ttl_seconds,
            "customIdentifier": _turn_scope_identifier(request),
        }
        try:
            if self._client is None:
                async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                    response = await client.post(url, headers=headers, json=payload)
            else:
                response = await self._client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as error:
            raise TurnCredentialProviderError(
                "Cloudflare TURN credential request failed"
            ) from error

        if not 200 <= response.status_code < 300:
            raise TurnCredentialProviderError(
                f"Cloudflare TURN credential request failed with status {response.status_code}"
            )
        try:
            response_payload = response.json()
        except (TypeError, ValueError) as error:
            raise TurnCredentialProviderError(
                "Cloudflare returned an invalid TURN response"
            ) from error
        urls, username, credential = _parse_cloudflare_credentials(response_payload)
        expires_at = int(self._clock() * 1_000) + request.ttl_seconds * 1_000
        return TurnCredentials(
            urls=urls,
            username=username,
            credential=credential,
            expires_at=expires_at,
        )


def create_turn_credential_provider(
    app_env: AppEnvironment,
    adapter: str,
    *,
    turn_key_id: str | None = None,
    api_token: str | None = None,
) -> TurnCredentialProvider:
    """Build the configured TURN provider without substituting a fake in production."""

    if adapter == "fake":
        return FakeTurnCredentialProvider(app_env=app_env)
    if adapter == "disabled":
        return DisabledTurnCredentialProvider()
    if adapter == "cloudflare":
        if turn_key_id is None or api_token is None:
            raise ConfigurationError(
                "Cloudflare TURN credentials must be configured before startup"
            )
        return CloudflareTurnCredentialProvider(
            turn_key_id=turn_key_id,
            api_token=api_token,
        )
    raise ConfigurationError(f"unsupported TURN adapter: {adapter}")


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
