import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.repositories import (
    DeviceChallengeRepository,
    PairingRequestRepository,
    WebSocketTicketRepository,
)


class OwnershipRecordingDatabase:
    def __init__(self, owner_id: UUID, row: dict[str, object]) -> None:
        self.owner_id = owner_id
        self.row = row
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        self.calls.append((query, parameters))
        return [self.row] if parameters and parameters[0] == self.owner_id else []


class AtomicOneTimeDatabase:
    def __init__(self, owner_id: UUID, row: dict[str, object]) -> None:
        self.owner_id = owner_id
        self.row = row
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.transaction_events: list[str] = []
        self._consumed = False
        self._lock = asyncio.Lock()

    def transaction(self) -> "AtomicOneTimeDatabase":
        return self

    async def __aenter__(self) -> "AtomicOneTimeDatabase":
        self.transaction_events.append("begin")
        return self

    async def __aexit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.transaction_events.append("commit" if exc_type is None else "rollback")

    async def fetch(self, query: str, *parameters: object) -> list[object]:
        self.calls.append((query, parameters))
        async with self._lock:
            if not parameters or parameters[0] != self.owner_id or self._consumed:
                return []
            self._consumed = True
            consumed_row = self.row.copy()
            consumed_row["consumed_at"] = datetime(2026, 1, 2, tzinfo=UTC)
            if "pairing_requests" in query:
                consumed_row["status"] = "consumed"
            return [consumed_row]


def _challenge_row() -> dict[str, object]:
    return {
        "id": uuid4(),
        "device_id": uuid4(),
        "nonce_hash": b"n" * 32,
        "origin": "https://app.example.test",
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "expires_at": datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        "consumed_at": None,
        "attempt_count": 0,
    }


def _pairing_row(account_id: UUID) -> dict[str, object]:
    return {
        "id": uuid4(),
        "user_id": account_id,
        "requested_public_key_spki": b"spki",
        "requested_fingerprint": b"f" * 32,
        "requested_label": "Laptop",
        "request_nonce": b"r" * 16,
        "comparison_code_hash": b"c" * 32,
        "status": "approved",
        "attempt_count": 0,
        "approved_by_device_id": uuid4(),
        "approval_signature": b"s" * 32,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "expires_at": datetime(2026, 1, 1, 0, 10, tzinfo=UTC),
        "consumed_at": None,
    }


def _ticket_row() -> dict[str, object]:
    return {
        "id": uuid4(),
        "session_id": uuid4(),
        "token_hash": b"t" * 32,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "expires_at": datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        "consumed_at": None,
    }


def test_one_time_lookups_isolate_foreign_accounts() -> None:
    async def exercise() -> None:
        owner_id = uuid4()
        foreign_id = uuid4()

        challenge_row = _challenge_row()
        challenge_id = challenge_row["id"]
        assert isinstance(challenge_id, UUID)
        challenge_database = OwnershipRecordingDatabase(owner_id, challenge_row)
        challenge_repository = DeviceChallengeRepository(challenge_database)
        assert await challenge_repository.get_by_id(owner_id, challenge_id) is not None
        assert await challenge_repository.get_by_id(foreign_id, challenge_id) is None

        pairing_row = _pairing_row(owner_id)
        pairing_id = pairing_row["id"]
        assert isinstance(pairing_id, UUID)
        pairing_database = OwnershipRecordingDatabase(owner_id, pairing_row)
        pairing_repository = PairingRequestRepository(pairing_database)
        assert await pairing_repository.get_by_id(owner_id, pairing_id) is not None
        assert await pairing_repository.get_by_id(foreign_id, pairing_id) is None

        ticket_row = _ticket_row()
        ticket_id = ticket_row["id"]
        assert isinstance(ticket_id, UUID)
        ticket_database = OwnershipRecordingDatabase(owner_id, ticket_row)
        ticket_repository = WebSocketTicketRepository(ticket_database)
        assert await ticket_repository.get_by_id(owner_id, ticket_id) is not None
        assert await ticket_repository.get_by_id(foreign_id, ticket_id) is None

        assert all(
            parameters[0] in (owner_id, foreign_id) for _, parameters in challenge_database.calls
        )
        assert all(
            "user_id = $1" in query or "account.id = $1" in query
            for query, _ in pairing_database.calls
        )
        assert all("account.id = $1" in query for query, _ in ticket_database.calls)

    asyncio.run(exercise())


def test_one_time_consumption_allows_only_one_concurrent_winner() -> None:
    async def exercise() -> None:
        account_id = uuid4()

        challenge_row = _challenge_row()
        challenge_id = challenge_row["id"]
        assert isinstance(challenge_id, UUID)
        challenge_database = AtomicOneTimeDatabase(account_id, challenge_row)
        challenge_repository = DeviceChallengeRepository(challenge_database)
        challenge_results = await asyncio.gather(
            challenge_repository.consume(account_id, challenge_id),
            challenge_repository.consume(account_id, challenge_id),
        )
        assert sum(result is not None for result in challenge_results) == 1
        assert all(
            "consumed_at IS NULL" in query and "expires_at > CURRENT_TIMESTAMP" in query
            for query, _ in challenge_database.calls
        )

        pairing_row = _pairing_row(account_id)
        pairing_id = pairing_row["id"]
        assert isinstance(pairing_id, UUID)
        pairing_database = AtomicOneTimeDatabase(account_id, pairing_row)
        pairing_repository = PairingRequestRepository(pairing_database)
        pairing_results = await asyncio.gather(
            pairing_repository.consume(account_id, pairing_id),
            pairing_repository.consume(account_id, pairing_id),
        )
        assert sum(result is not None for result in pairing_results) == 1
        assert all(
            "status = 'approved'" in query and "consumed_at IS NULL" in query
            for query, _ in pairing_database.calls
        )

        ticket_row = _ticket_row()
        token_hash = ticket_row["token_hash"]
        assert isinstance(token_hash, bytes)
        ticket_database = AtomicOneTimeDatabase(account_id, ticket_row)
        ticket_repository = WebSocketTicketRepository(ticket_database)
        ticket_results = await asyncio.gather(
            ticket_repository.consume(account_id, token_hash),
            ticket_repository.consume(account_id, token_hash),
        )
        assert sum(result is not None for result in ticket_results) == 1
        assert all(
            "token_hash = $2" in query and "consumed_at IS NULL" in query
            for query, _ in ticket_database.calls
        )

        assert challenge_database.transaction_events == [
            "begin",
            "commit",
            "begin",
            "commit",
        ]
        assert pairing_database.transaction_events == [
            "begin",
            "commit",
            "begin",
            "commit",
        ]
        assert ticket_database.transaction_events == [
            "begin",
            "commit",
            "begin",
            "commit",
        ]

    asyncio.run(exercise())
