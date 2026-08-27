import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.repositories import (
    AccountRecord,
    AccountRepository,
    DeviceRecord,
    DeviceRepository,
    SessionRecord,
    SessionRepository,
)


class RecordingDatabase:
    def __init__(self, row: dict[str, object] | None) -> None:
        self.row = row
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        self.calls.append((query, parameters))
        return [] if self.row is None else [self.row]


class TransactionRecordingDatabase:
    def __init__(self, responses: list[list[object]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.transaction_events: list[str] = []

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        self.calls.append((query, parameters))
        return self.responses.pop(0)

    def transaction(self) -> "TransactionRecordingDatabase":
        return self

    async def __aenter__(self) -> "TransactionRecordingDatabase":
        self.transaction_events.append("begin")
        return self

    async def __aexit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.transaction_events.append("commit" if exc_type is None else "rollback")


def _account_row() -> dict[str, object]:
    return {
        "id": uuid4(),
        "supabase_user_id": uuid4(),
        "email_normalized": "alice@example.test",
        "device_epoch": 0,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "recovered_at": None,
        "deleted_at": None,
    }


def _device_row(account_id: UUID) -> dict[str, object]:
    return {
        "id": uuid4(),
        "user_id": account_id,
        "epoch": 0,
        "label": "Laptop",
        "signing_public_key_spki": b"spki",
        "fingerprint": b"f" * 32,
        "status": "revoked",
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "last_seen_at": datetime(2026, 1, 2, tzinfo=UTC),
        "revoked_at": datetime(2026, 1, 3, tzinfo=UTC),
        "approved_by_device_id": None,
    }


def _session_row(account_id: UUID, device_id: UUID) -> dict[str, object]:
    return {
        "id": uuid4(),
        "user_id": account_id,
        "device_id": device_id,
        "token_hash": b"t" * 32,
        "csrf_hash": b"c" * 32,
        "epoch": 0,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "last_seen_at": datetime(2026, 1, 2, tzinfo=UTC),
        "idle_expires_at": datetime(2026, 2, 1, tzinfo=UTC),
        "absolute_expires_at": datetime(2026, 4, 1, tzinfo=UTC),
        "revoked_at": None,
        "revocation_reason": None,
    }


def test_account_lookup_is_parameterized_and_returns_typed_record() -> None:
    async def exercise() -> None:
        row = _account_row()
        database = RecordingDatabase(row)
        repository = AccountRepository(database)
        supabase_user_id = row["supabase_user_id"]
        assert isinstance(supabase_user_id, UUID)

        result = await repository.get_by_supabase_user_id(supabase_user_id)

        assert isinstance(result, AccountRecord)
        assert result.id == row["id"]
        query, parameters = database.calls[0]
        assert "supabase_user_id = $1" in query
        assert str(supabase_user_id) not in query
        assert parameters == (supabase_user_id,)

    asyncio.run(exercise())


def test_account_creation_passes_identity_and_email_as_parameters() -> None:
    async def exercise() -> None:
        row = _account_row()
        database = RecordingDatabase(row)
        repository = AccountRepository(database)
        supabase_user_id = row["supabase_user_id"]
        email = row["email_normalized"]
        assert isinstance(supabase_user_id, UUID)
        assert isinstance(email, str)

        result = await repository.create(supabase_user_id, email)

        assert result.email_normalized == email
        query, parameters = database.calls[0]
        assert "VALUES ($1, $2)" in query
        assert email not in query
        assert parameters == (supabase_user_id, email)

    asyncio.run(exercise())


def test_missing_account_lookup_returns_none() -> None:
    async def exercise() -> None:
        database = RecordingDatabase(None)
        repository = AccountRepository(database)

        result = await repository.get_by_id(uuid4())

        assert result is None

    asyncio.run(exercise())


def test_device_lookup_and_session_lookup_bind_account_and_secret_values() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        device_row = _device_row(account_id)
        device_id = device_row["id"]
        assert isinstance(device_id, UUID)
        device_database = RecordingDatabase(device_row)
        device = await DeviceRepository(device_database).get_by_id(account_id, device_id)

        assert isinstance(device, DeviceRecord)
        device_query, device_parameters = device_database.calls[0]
        assert "user_id = $1 AND id = $2" in device_query
        assert device_parameters == (account_id, device_id)

        session_row = _session_row(account_id, device_id)
        session_database = RecordingDatabase(session_row)
        token_hash = session_row["token_hash"]
        assert isinstance(token_hash, bytes)
        session = await SessionRepository(session_database).get_by_token_hash(
            account_id,
            token_hash,
        )

        assert isinstance(session, SessionRecord)
        session_query, session_parameters = session_database.calls[0]
        assert "user_id = $1" in session_query
        assert "token_hash = $2" in session_query
        assert token_hash.hex() not in session_query
        assert session_parameters == (account_id, token_hash)

    asyncio.run(exercise())


def test_device_revoke_uses_one_transaction_for_device_and_sessions() -> None:
    async def exercise() -> None:
        account_id = uuid4()
        device_row = _device_row(account_id)
        device_id = device_row["id"]
        assert isinstance(device_id, UUID)
        database = TransactionRecordingDatabase([[device_row], []])

        result = await DeviceRepository(database).revoke(account_id, device_id)

        assert isinstance(result, DeviceRecord)
        assert database.transaction_events == ["begin", "commit"]
        assert len(database.calls) == 2
        device_query, device_parameters = database.calls[0]
        session_query, session_parameters = database.calls[1]
        assert "WHERE user_id = $1 AND id = $2" in device_query
        assert "WHERE user_id = $1" in session_query
        assert "AND device_id = $2" in session_query
        assert device_parameters == (account_id, device_id)
        assert session_parameters == (account_id, device_id, "device_revoked")

    asyncio.run(exercise())
