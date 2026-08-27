import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.repositories import AccountRecord, AccountRepository


class RecordingDatabase:
    def __init__(self, row: dict[str, object] | None) -> None:
        self.row = row
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        self.calls.append((query, parameters))
        return [] if self.row is None else [self.row]


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
