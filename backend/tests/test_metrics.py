from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import pytest
from fastapi import WebSocket

from app.adapters import (
    FakeTurnCredentialProvider,
    TurnCredentialProvider,
    TurnCredentialProviderError,
    TurnCredentialRequest,
    TurnCredentials,
)
from app.auth import RateLimiterPort
from app.metrics import RuntimeMetrics
from app.presence import ActiveConnection, PresenceManager
from app.repositories.models import DeviceRecord, SessionRecord
from app.repositories.transfers import InMemoryTransferRequestRepository
from app.transfers import TransferService
from app.turn import (
    TurnCredentialRateLimitedError,
    TurnCredentialService,
    TurnProviderUnavailableError,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
SENSITIVE_FRAGMENTS = (
    "sdp",
    "candidate",
    "credential_value",
    "username",
    "password",
    "token",
    "filename",
    "mime",
    "ciphertext",
)


class QuietSocket:
    async def send_json(self, payload: dict[str, object]) -> None:
        return None

    async def close(self, code: int = 1000) -> None:
        return None


class StaticLimiter:
    def __init__(self, allowed: bool) -> None:
        self.allowed = allowed

    def allow_many(self, buckets: object, *, now: datetime | None = None) -> bool:
        return self.allowed


class FailingProvider:
    async def issue_credentials(self, request: TurnCredentialRequest) -> TurnCredentials:
        raise TurnCredentialProviderError("provider unavailable")


def _device(account_id: UUID, device_id: UUID) -> DeviceRecord:
    return DeviceRecord(
        id=device_id,
        user_id=account_id,
        epoch=0,
        label=str(device_id),
        signing_public_key_spki=b"spki",
        fingerprint=b"f" * 32,
        status="active",
        created_at=NOW,
        last_seen_at=NOW,
        revoked_at=None,
        linked_by_device_id=None,
    )


class Devices:
    def __init__(self, records: list[DeviceRecord]) -> None:
        self.records = {record.id: record for record in records}

    async def get_by_id(self, account_id: UUID, device_id: UUID) -> DeviceRecord | None:
        record = self.records.get(device_id)
        return record if record is not None and record.user_id == account_id else None


def _session(account_id: UUID, device_id: UUID) -> SessionRecord:
    return SessionRecord(
        id=uuid4(),
        user_id=account_id,
        device_id=device_id,
        token_hash=b"t" * 32,
        csrf_hash=b"c" * 32,
        epoch=0,
        created_at=NOW,
        last_seen_at=NOW,
        idle_expires_at=NOW + timedelta(hours=1),
        absolute_expires_at=NOW + timedelta(hours=8),
        revoked_at=None,
        revocation_reason=None,
    )


def _connection(account_id: UUID, device_id: UUID) -> ActiveConnection:
    return ActiveConnection(
        id=uuid4(),
        account_id=account_id,
        device_id=device_id,
        session_id=uuid4(),
        websocket=cast(WebSocket, QuietSocket()),
        connected_at=NOW,
        last_heartbeat_at=NOW,
    )


@dataclass(frozen=True, slots=True)
class TurnEnvironment:
    """One assembled TURN issuance path with its own counters."""

    service: TurnCredentialService
    metrics: RuntimeMetrics
    transfers: TransferService
    session: SessionRecord
    account_id: UUID
    sender_id: UUID
    recipient_id: UUID


def _turn_environment(
    provider: TurnCredentialProvider,
    allowed: bool = True,
) -> TurnEnvironment:
    account_id, sender_id, recipient_id = uuid4(), uuid4(), uuid4()
    devices = Devices([_device(account_id, sender_id), _device(account_id, recipient_id)])
    repository = InMemoryTransferRequestRepository(devices, clock=lambda: NOW)
    transfers = TransferService(repository, None, devices, clock=lambda: NOW)
    metrics = RuntimeMetrics()
    return TurnEnvironment(
        service=TurnCredentialService(
            provider,
            transfers,
            devices,
            cast(RateLimiterPort, StaticLimiter(allowed)),
            clock=lambda: NOW,
            metrics=metrics,
        ),
        metrics=metrics,
        transfers=transfers,
        session=_session(account_id, sender_id),
        account_id=account_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
    )


async def _accepted_offer(environment: TurnEnvironment) -> UUID:
    offer = await environment.transfers.create_offer(
        environment.account_id,
        environment.sender_id,
        environment.recipient_id,
    )
    await environment.transfers.accept(
        environment.account_id,
        offer.id,
        environment.recipient_id,
    )
    return offer.id


def test_counters_reject_invalid_names_and_amounts() -> None:
    metrics = RuntimeMetrics()

    with pytest.raises(ValueError):
        metrics.increment("")
    with pytest.raises(ValueError):
        metrics.increment("socket_registered", -1)

    metrics.increment("socket_registered", 2)
    assert metrics.value("socket_registered") == 2
    assert metrics.value("never_touched") == 0


def test_turn_issuance_before_and_after_acceptance_are_counted() -> None:
    async def exercise() -> None:
        environment = _turn_environment(FakeTurnCredentialProvider(app_env="test"))
        offer = await environment.transfers.create_offer(
            environment.account_id,
            environment.sender_id,
            environment.recipient_id,
        )

        offered_credentials = await environment.service.issue(
            environment.session,
            offer.id,
            "203.0.113.7",
        )
        assert offered_credentials.username
        assert environment.metrics.value("turn_credential_issued") == 1

        await environment.transfers.accept(
            environment.account_id, offer.id, environment.recipient_id
        )
        credentials = await environment.service.issue(environment.session, offer.id, "203.0.113.7")

        assert credentials.username
        assert environment.metrics.value("turn_credential_issued") == 2

    asyncio.run(exercise())


def test_turn_rate_limit_rejections_are_counted() -> None:
    async def exercise() -> None:
        environment = _turn_environment(
            FakeTurnCredentialProvider(app_env="test"),
            allowed=False,
        )
        transfer_id = await _accepted_offer(environment)

        with pytest.raises(TurnCredentialRateLimitedError):
            await environment.service.issue(environment.session, transfer_id, "203.0.113.7")

        assert environment.metrics.value("turn_credential_rate_limited") == 1
        assert environment.metrics.value("turn_credential_issued") == 0

    asyncio.run(exercise())


def test_turn_provider_failures_are_counted() -> None:
    async def exercise() -> None:
        environment = _turn_environment(FailingProvider())
        transfer_id = await _accepted_offer(environment)

        with pytest.raises(TurnProviderUnavailableError):
            await environment.service.issue(environment.session, transfer_id, "203.0.113.7")

        assert environment.metrics.value("turn_provider_failed") == 1
        assert environment.metrics.value("turn_credential_issued") == 0

    asyncio.run(exercise())


def test_resource_gauges_report_socket_and_queue_occupancy() -> None:
    async def exercise() -> None:
        manager = PresenceManager(clock=lambda: NOW)
        account_id, device_id = uuid4(), uuid4()
        await manager.register(_connection(account_id, device_id))

        snapshot = await manager.resource_snapshot()

        assert snapshot["active_sockets"] == 1
        assert snapshot["active_signaling_transfers"] == 0
        assert snapshot["queued_messages"] >= 0
        assert snapshot["queued_bytes"] >= 0
        await manager.close_all()

    asyncio.run(exercise())


def test_peer_reported_connection_mode_is_counted_only_for_participants() -> None:
    async def exercise() -> None:
        account_id, sender_id, recipient_id = uuid4(), uuid4(), uuid4()
        devices = Devices([_device(account_id, sender_id), _device(account_id, recipient_id)])
        repository = InMemoryTransferRequestRepository(devices, clock=lambda: NOW)
        manager = PresenceManager(devices, transfer_repository=repository, clock=lambda: NOW)
        transfers = TransferService(repository, manager, devices, clock=lambda: NOW)
        offer = await transfers.create_offer(account_id, sender_id, recipient_id)
        connection = _connection(account_id, sender_id)
        stranger = _connection(account_id, uuid4())
        message: dict[str, object] = {
            "type": "connection_mode",
            "v": 1,
            "transfer_id": str(offer.id),
            "mode": "relay",
        }

        assert await manager.record_connection_mode(connection, message)
        assert not await manager.record_connection_mode(stranger, message)
        assert not await manager.record_connection_mode(connection, {**message, "mode": "carrier"})

        assert manager.metrics.value("webrtc_relay") == 1
        assert manager.metrics.value("webrtc_direct") == 0
        recorded_transfer = await repository.get_by_id(account_id, offer.id)
        assert recorded_transfer is not None
        assert recorded_transfer.relay_used

    asyncio.run(exercise())


def test_metric_names_never_carry_connection_or_cryptographic_material() -> None:
    async def exercise() -> None:
        account_id, sender_id, recipient_id = uuid4(), uuid4(), uuid4()
        devices = Devices([_device(account_id, sender_id), _device(account_id, recipient_id)])
        repository = InMemoryTransferRequestRepository(devices, clock=lambda: NOW)
        manager = PresenceManager(devices, transfer_repository=repository, clock=lambda: NOW)
        transfers = TransferService(repository, manager, devices, clock=lambda: NOW)
        offer = await transfers.create_offer(account_id, sender_id, recipient_id)
        connection = _connection(account_id, sender_id)
        await manager.register(connection)
        await manager.record_connection_mode(
            connection,
            {
                "type": "connection_mode",
                "v": 1,
                "transfer_id": str(offer.id),
                "mode": "direct",
            },
        )

        names = list(manager.metrics.snapshot())
        identifiers = {str(account_id), str(sender_id), str(recipient_id), str(offer.id)}

        assert names
        for name in names:
            assert name.replace("_", "").isalnum()
            assert name not in identifiers
            assert not any(fragment in name for fragment in SENSITIVE_FRAGMENTS)
        await manager.close_all()

    asyncio.run(exercise())
