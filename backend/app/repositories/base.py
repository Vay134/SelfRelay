"""Shared types and row helpers for repository implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, cast

QueryRow = Mapping[str, object]


class RepositoryDatabase(Protocol):
    """Database operations required by the core repositories."""

    async def fetch(self, query: str, *parameters: object) -> list[object]: ...


def first_row(rows: list[object]) -> QueryRow | None:
    """Return the first row from a query result, if one was returned."""

    if not rows:
        return None
    return cast(QueryRow, rows[0])


def as_row(value: object) -> QueryRow:
    """Treat an asyncpg record or mapping returned by a fake as one row."""

    return cast(QueryRow, value)


def required_row(rows: list[object]) -> QueryRow:
    """Return one expected row or fail loudly on a malformed database result."""

    row = first_row(rows)
    if row is None:
        raise RuntimeError("database did not return the requested record")
    return row
