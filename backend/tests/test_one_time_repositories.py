from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.repositories import DeviceLinkingOtpRepository


class RecordingDatabase:
    def __init__(self, otp_row: dict[str, object], device_row: dict[str, object]) -> None:
        self.otp_row = otp_row
        self.device_row = device_row
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.transaction_events: list[str] = []
        self.consumed = False

    def transaction(self) -> 'RecordingDatabase':
        return self

    async def __aenter__(self) -> 'RecordingDatabase':
        self.transaction_events.append('begin')
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.transaction_events.append('rollback' if exc_type else 'commit')

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        self.calls.append((query, parameters))
        if query.lstrip().startswith('UPDATE private.device_linking_otps AS otp'):
            if self.consumed:
                return []
            self.consumed = True
            return [{'id': self.otp_row['id']}]
        if query.lstrip().startswith('INSERT INTO private.devices'):
            return [self.device_row]
        return [self.otp_row]


def _otp_row(account_id: UUID) -> dict[str, object]:
    return {
        'id': uuid4(),
        'user_id': account_id,
        'issuing_device_id': uuid4(),
        'otp_hash': b'h' * 32,
        'status': 'active',
        'attempt_count': 0,
        'created_at': datetime(2026, 1, 1, tzinfo=UTC),
        'expires_at': datetime(2026, 1, 1, 0, 10, tzinfo=UTC),
        'consumed_at': None,
    }


def _device_row(account_id: UUID, device_id: UUID) -> dict[str, object]:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return {
        'id': device_id,
        'user_id': account_id,
        'epoch': 0,
        'label': 'Linked browser',
        'signing_public_key_spki': b'spki',
        'fingerprint': b'f' * 32,
        'status': 'active',
        'created_at': now,
        'last_seen_at': now,
        'revoked_at': None,
        'linked_by_device_id': uuid4(),
    }


def test_linking_otp_lookup_is_account_bound_and_expiry_checked() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        row = _otp_row(account_id)
        database = RecordingDatabase(row, _device_row(account_id, uuid4()))
        repository = DeviceLinkingOtpRepository(database)

        found = await repository.get_active_by_hash(cast_bytes(row['otp_hash']))
        assert found is not None
        assert found.user_id == account_id
        query, parameters = database.calls[0]
        assert parameters == (row['otp_hash'],)
        assert 'otp.status = \'active\'' in query
        assert 'otp.expires_at > CURRENT_TIMESTAMP' in query

    asyncio.run(exercise())


def test_linking_otp_redemption_consumes_once_with_the_new_device() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        row = _otp_row(account_id)
        issuer_id = cast_uuid(row['issuing_device_id'])
        device_id = uuid4()
        database = RecordingDatabase(row, _device_row(account_id, device_id))
        repository = DeviceLinkingOtpRepository(database)

        results = await asyncio.gather(
            repository.consume_and_register(
                cast_uuid(row['id']),
                account_id,
                issuer_id,
                0,
                device_id,
                'Linked browser',
                b'spki',
                b'f' * 32,
            ),
            repository.consume_and_register(
                cast_uuid(row['id']),
                account_id,
                issuer_id,
                0,
                uuid4(),
                'Second browser',
                b'spki2',
                b'g' * 32,
            ),
        )
        assert sum(result is not None for result in results) == 1
        assert database.transaction_events == ['begin', 'commit', 'begin', 'commit']
        assert any('status = \'active\'' in query for query, _ in database.calls)
        assert any('linked_by_device_id' in query for query, _ in database.calls)

    asyncio.run(exercise())


def cast_uuid(value: object) -> UUID:
    assert isinstance(value, UUID)
    return value


def cast_bytes(value: object) -> bytes:
    assert isinstance(value, bytes)
    return value
