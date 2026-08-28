import asyncio
import hashlib
import json

import httpx
import pytest

from app.adapters import (
    AuthGateway,
    CloudflareTurnCredentialProvider,
    FakeAuthGateway,
    FakeTurnCredentialProvider,
    InvalidOtpError,
    TurnCredentialProvider,
    TurnCredentialProviderError,
    TurnCredentialRequest,
    create_turn_credential_provider,
)
from app.config import ConfigurationError


def test_fake_adapters_are_typed_ports_and_require_test_environment() -> None:
    auth: AuthGateway = FakeAuthGateway()
    turn: TurnCredentialProvider = FakeTurnCredentialProvider()

    assert auth is not None
    assert turn is not None
    with pytest.raises(ConfigurationError, match="test environment"):
        FakeAuthGateway(app_env="development")
    with pytest.raises(ConfigurationError, match="test environment"):
        FakeTurnCredentialProvider(app_env="production")


def test_fake_auth_gateway_issues_deterministic_one_time_otps() -> None:
    async def exercise() -> None:
        first = FakeAuthGateway()
        second = FakeAuthGateway()

        await first.start_otp("Alice@example.test")
        await second.start_otp("Alice@example.test")
        otp = first.otp_for("Alice@example.test")

        assert otp == second.otp_for("Alice@example.test")
        assert len(otp) == 6
        assert first.requested_emails == ("Alice@example.test",)

        identity = await first.verify_otp("Alice@example.test", otp)
        second_identity = await second.verify_otp(
            "Alice@example.test", second.otp_for("Alice@example.test")
        )
        assert identity == second_identity
        assert identity.email == "Alice@example.test"
        with pytest.raises(InvalidOtpError, match="invalid OTP"):
            await first.verify_otp("Alice@example.test", otp)

    asyncio.run(exercise())


def test_fake_auth_gateway_rejects_unknown_or_wrong_otps() -> None:
    async def exercise() -> None:
        gateway = FakeAuthGateway()

        with pytest.raises(InvalidOtpError, match="invalid OTP"):
            await gateway.verify_otp("unknown@example.test", "123456")
        await gateway.start_otp("known@example.test")
        with pytest.raises(InvalidOtpError, match="invalid OTP"):
            await gateway.verify_otp("known@example.test", "123456")

    asyncio.run(exercise())


def test_fake_turn_provider_is_deterministic_and_records_scope() -> None:
    async def exercise() -> None:
        request = TurnCredentialRequest(
            account_id="account-1",
            device_id="device-1",
            transfer_id="transfer-1",
            ttl_seconds=120,
        )
        first = FakeTurnCredentialProvider()
        second = FakeTurnCredentialProvider()

        credentials = await first.issue_credentials(request)
        assert credentials == await second.issue_credentials(request)
        assert credentials.urls == (
            "stun:turn.test.invalid",
            "turn:turn.test.invalid?transport=udp",
        )
        assert credentials.expires_at == 1_700_000_120_000
        assert first.requests == (request,)

    asyncio.run(exercise())


def test_fake_turn_provider_rejects_non_positive_ttl() -> None:
    async def exercise() -> None:
        provider = FakeTurnCredentialProvider()
        request = TurnCredentialRequest("account", "device", "transfer", 0)

        with pytest.raises(ValueError, match="TTL must be positive"):
            await provider.issue_credentials(request)

    asyncio.run(exercise())


def test_turn_provider_factory_builds_fake_and_cloudflare_adapters() -> None:
    assert isinstance(create_turn_credential_provider("test", "fake"), FakeTurnCredentialProvider)
    assert isinstance(
        create_turn_credential_provider(
            "production",
            "cloudflare",
            turn_key_id="key-id",
            api_token="api-token",
        ),
        CloudflareTurnCredentialProvider,
    )
    with pytest.raises(ConfigurationError, match="Cloudflare TURN credentials"):
        create_turn_credential_provider("production", "cloudflare")


def test_cloudflare_turn_provider_posts_scoped_request_and_maps_ice_servers() -> None:
    async def exercise() -> None:
        request = TurnCredentialRequest("account-1", "device-1", "transfer-1", 120)
        expected_identifier = hashlib.sha256(
            b"turn:account-1\x00device-1\x00transfer-1"
        ).hexdigest()

        async def handler(http_request: httpx.Request) -> httpx.Response:
            assert http_request.method == "POST"
            assert str(http_request.url) == (
                "https://rtc.live.cloudflare.com/v1/turn/keys/key-id/credentials/"
                "generate-ice-servers"
            )
            assert http_request.headers["authorization"] == "Bearer api-token"
            assert http_request.headers["content-type"] == "application/json"
            assert json.loads(http_request.content) == {
                "ttl": 120,
                "customIdentifier": expected_identifier,
            }
            return httpx.Response(
                201,
                json={
                    "iceServers": [
                        {"urls": ["stun:stun.cloudflare.com:3478"]},
                        {
                            "urls": [
                                "turn:turn.cloudflare.com:3478?transport=udp",
                                "turns:turn.cloudflare.com:443?transport=tcp",
                            ],
                            "username": "cloudflare-user",
                            "credential": "cloudflare-credential",
                        },
                    ]
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider = CloudflareTurnCredentialProvider(
                turn_key_id="key-id",
                api_token="api-token",
                client=client,
                clock=lambda: 1_700_000_000,
            )
            credentials = await provider.issue_credentials(request)

        assert credentials.urls == (
            "stun:stun.cloudflare.com:3478",
            "turn:turn.cloudflare.com:3478?transport=udp",
            "turns:turn.cloudflare.com:443?transport=tcp",
        )
        assert credentials.username == "cloudflare-user"
        assert credentials.credential == "cloudflare-credential"
        assert credentials.expires_at == 1_700_000_120_000

    asyncio.run(exercise())


def test_cloudflare_turn_provider_hides_http_failures_and_rejects_bad_responses() -> None:
    async def exercise() -> None:
        request = TurnCredentialRequest("account", "device", "transfer", 120)

        async def failure_handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="provider-token should never be exposed")

        async with httpx.AsyncClient(transport=httpx.MockTransport(failure_handler)) as client:
            provider = CloudflareTurnCredentialProvider(
                turn_key_id="key-id",
                api_token="api-token",
                client=client,
            )
            with pytest.raises(TurnCredentialProviderError) as error:
                await provider.issue_credentials(request)
        assert "provider-token" not in str(error.value)
        assert "api-token" not in str(error.value)

        async def malformed_handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"iceServers": [{"urls": ["stun:only.test"]}]})

        async with httpx.AsyncClient(transport=httpx.MockTransport(malformed_handler)) as client:
            provider = CloudflareTurnCredentialProvider(
                turn_key_id="key-id",
                api_token="api-token",
                client=client,
            )
            with pytest.raises(TurnCredentialProviderError, match="incomplete TURN credentials"):
                await provider.issue_credentials(request)

    asyncio.run(exercise())


def test_cloudflare_turn_provider_rejects_ttl_above_provider_limit() -> None:
    async def exercise() -> None:
        provider = CloudflareTurnCredentialProvider(turn_key_id="key-id", api_token="api-token")
        request = TurnCredentialRequest("account", "device", "transfer", 48 * 60 * 60 + 1)

        with pytest.raises(ValueError, match="48 hour maximum"):
            await provider.issue_credentials(request)

    asyncio.run(exercise())
