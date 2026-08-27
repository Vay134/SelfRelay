import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.repositories import (
    CleanupRepository,
    ExpiryCleanupRepository,
    RateLimitBucketRepository,
    SecurityEventRepository,
    TransferRequestRecord,
    TransferRequestRepository,
)


class RecordingDatabase:
    def __init__(self, responses: list[list[object]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        self.calls.append((query, parameters))
        return self.responses.pop(0)


class TransactionRecordingDatabase(RecordingDatabase):
    def __init__(self, responses: list[list[object]]) -> None:
        super().__init__(responses)
        self.transaction_events: list[str] = []

    def transaction(self) -> "TransactionRecordingDatabase":
        return self

    async def __aenter__(self) -> "TransactionRecordingDatabase":
        self.transaction_events.append("begin")
        return self

    async def __aexit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.transaction_events.append("commit" if exc_type is None else "rollback")


def _transfer_row(account_id: UUID) -> dict[str, object]:
    return {
        "id": uuid4(),
        "user_id": account_id,
        "sender_device_id": uuid4(),
        "recipient_device_id": uuid4(),
        "protocol_version": 1,
        "status": "offered",
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "expires_at": datetime(2026, 1, 1, 0, 10, tzinfo=UTC),
        "accepted_at": None,
        "completed_at": None,
        "failure_code": None,
        "relay_used": False,
    }


def _event_row(account_id: UUID) -> dict[str, object]:
    return {
        "id": uuid4(),
        "user_id": account_id,
        "device_id": uuid4(),
        "event_type": "otp_failed",
        "outcome": "failure",
        "network_fingerprint": b"n" * 32,
        "details": {"attempt": 1},
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "expires_at": datetime(2026, 2, 1, tzinfo=UTC),
    }


def _bucket_row() -> dict[str, object]:
    return {
        "scope": "otp:account",
        "bucket_key": b"k" * 32,
        "window_started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "window_expires_at": datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        "request_count": 1,
    }


def test_transfer_creation_and_transition_are_owned_and_parameterized() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        row = _transfer_row(account_id)
        transfer_id = row["id"]
        sender_id = row["sender_device_id"]
        recipient_id = row["recipient_device_id"]
        assert isinstance(transfer_id, UUID)
        assert isinstance(sender_id, UUID)
        assert isinstance(recipient_id, UUID)
        database = RecordingDatabase([[row], [row]])
        repository = TransferRequestRepository(database)

        created = await repository.create(
            account_id,
            sender_id,
            recipient_id,
            1,
            row["expires_at"],  # type: ignore[arg-type]
        )
        accepted = await repository.accept(account_id, transfer_id, recipient_id)

        assert isinstance(created, TransferRequestRecord)
        assert accepted is not None
        create_query, create_parameters = database.calls[0]
        assert "sender.user_id = account.id" in create_query
        assert "recipient.user_id = account.id" in create_query
        assert create_parameters == (account_id, sender_id, recipient_id, 1, row["expires_at"])
        accept_query, accept_parameters = database.calls[1]
        assert "status IN ('offered')" in accept_query
        assert "actor.id = transfer.recipient_device_id" in accept_query
        assert accept_parameters == (account_id, transfer_id, recipient_id)

    asyncio.run(exercise())


def test_transfer_rejects_invalid_state_transition_without_querying() -> None:
    async def exercise() -> None:
        database = RecordingDatabase([])
        repository = TransferRequestRepository(database)

        result = await repository.transition(uuid4(), uuid4(), "completed", "connected")

        assert result is None
        assert database.calls == []

    asyncio.run(exercise())


def test_security_events_serialize_details_and_keep_values_out_of_sql() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        event_row = _event_row(account_id)
        database = RecordingDatabase([[event_row]])
        repository = SecurityEventRepository(database)
        expires_at = event_row["expires_at"]
        assert isinstance(expires_at, datetime)

        result = await repository.create(
            "otp_failed",
            "failure",
            expires_at,
            user_id=account_id,
            details={"attempt": 1},
        )

        assert result.event_type == "otp_failed"
        query, parameters = database.calls[0]
        assert "$6::jsonb" in query
        assert "otp_failed" not in query
        assert parameters[:4] == (account_id, None, "otp_failed", "failure")
        assert parameters[5] == '{"attempt":1}'

    asyncio.run(exercise())


def test_rate_limit_increment_uses_atomic_upsert() -> None:
    async def exercise() -> None:
        row = _bucket_row()
        database = RecordingDatabase([[row]])
        repository = RateLimitBucketRepository(database)
        expires_at = row["window_expires_at"]
        assert isinstance(expires_at, datetime)

        result = await repository.increment("otp:account", b"k" * 32, expires_at)

        assert result.request_count == 1
        query, parameters = database.calls[0]
        assert "ON CONFLICT (scope, bucket_key) DO UPDATE" in query
        assert "request_count + 1" in query
        assert parameters == ("otp:account", b"k" * 32, expires_at)

    asyncio.run(exercise())


def test_expiry_cleanup_uses_one_transaction_and_a_bound_for_each_table() -> None:
    async def exercise() -> None:
        database = TransactionRecordingDatabase([([{"id": uuid4()}]) for _ in range(7)])
        repository = ExpiryCleanupRepository(database)

        result = await repository.cleanup_expired(batch_size=25)

        assert result == {
            "app_sessions": 1,
            "device_challenges": 1,
            "pairing_requests": 1,
            "transfer_requests": 1,
            "websocket_tickets": 1,
            "security_events": 1,
            "rate_limit_buckets": 1,
        }
        assert database.transaction_events == ["begin", "commit"]
        assert len(database.calls) == 7
        assert all(
            "LIMIT $1" in query and parameters == (25,) for query, parameters in database.calls
        )
        assert CleanupRepository is ExpiryCleanupRepository

    asyncio.run(exercise())


def test_expiry_cleanup_rejects_unbounded_batch_sizes_before_opening_transaction() -> None:
    async def exercise() -> None:
        database = TransactionRecordingDatabase([])
        repository = ExpiryCleanupRepository(database)

        try:
            await repository.cleanup_expired(batch_size=0)
        except ValueError as error:
            assert "batch_size" in str(error)
        else:
            raise AssertionError("expected invalid batch size to fail")
        assert database.transaction_events == []

    asyncio.run(exercise())
