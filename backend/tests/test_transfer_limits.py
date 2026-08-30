from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from app.repositories.models import DeviceRecord
from app.repositories.transfers import InMemoryTransferRequestRepository
from app.transfers import (
    MAX_ACTIVE_TRANSFERS_PER_ACCOUNT,
    MAX_ACTIVE_TRANSFERS_PER_DEVICE,
    TransferCapacityError,
    TransferService,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


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


def _service(account_id: UUID, device_ids: list[UUID]) -> TransferService:
    devices = Devices([_device(account_id, device_id) for device_id in device_ids])
    repository = InMemoryTransferRequestRepository(devices, clock=lambda: NOW)
    return TransferService(repository, None, devices, clock=lambda: NOW)


def test_a_device_pair_cannot_exceed_its_active_transfer_budget() -> None:
    async def exercise() -> None:
        account_id, sender_id, recipient_id = uuid4(), uuid4(), uuid4()
        service = _service(account_id, [sender_id, recipient_id])

        for _ in range(MAX_ACTIVE_TRANSFERS_PER_DEVICE):
            await service.create_offer(account_id, sender_id, recipient_id)

        with pytest.raises(TransferCapacityError):
            await service.create_offer(account_id, sender_id, recipient_id)

    asyncio.run(exercise())


def test_an_account_cannot_exceed_its_active_transfer_budget() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        device_ids = [uuid4() for _ in range(MAX_ACTIVE_TRANSFERS_PER_ACCOUNT + 2)]
        service = _service(account_id, device_ids)

        created = 0
        pairs = list(zip(device_ids, device_ids[1:], strict=False))
        for sender_id, recipient_id in pairs:
            try:
                await service.create_offer(account_id, sender_id, recipient_id)
            except TransferCapacityError:
                break
            created += 1

        assert created == MAX_ACTIVE_TRANSFERS_PER_ACCOUNT

    asyncio.run(exercise())


def test_cancelling_a_transfer_returns_capacity_to_the_device() -> None:
    async def exercise() -> None:
        account_id, sender_id, recipient_id = uuid4(), uuid4(), uuid4()
        service = _service(account_id, [sender_id, recipient_id])
        offers = [
            await service.create_offer(account_id, sender_id, recipient_id)
            for _ in range(MAX_ACTIVE_TRANSFERS_PER_DEVICE)
        ]

        await service.cancel(account_id, offers[0].id, sender_id)

        assert await service.create_offer(account_id, sender_id, recipient_id) is not None

    asyncio.run(exercise())
