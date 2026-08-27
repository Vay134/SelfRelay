import asyncio

import pytest

from app.adapters import (
    AuthGateway,
    FakeAuthGateway,
    FakeTurnCredentialProvider,
    InvalidOtpError,
    TurnCredentialProvider,
    TurnCredentialRequest,
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
