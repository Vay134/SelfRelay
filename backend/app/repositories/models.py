"""Typed records returned by the core repositories."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import cast
from uuid import UUID


@dataclass(frozen=True, slots=True)
class AccountRecord:
    """One application account linked to a Supabase Auth identity."""

    id: UUID
    supabase_user_id: UUID
    email_normalized: str
    device_epoch: int
    created_at: datetime
    recovered_at: datetime | None
    deleted_at: datetime | None


def account_from_row(row: Mapping[str, object]) -> AccountRecord:
    """Convert a database row into an immutable account record."""

    return AccountRecord(
        id=cast(UUID, row["id"]),
        supabase_user_id=cast(UUID, row["supabase_user_id"]),
        email_normalized=cast(str, row["email_normalized"]),
        device_epoch=cast(int, row["device_epoch"]),
        created_at=cast(datetime, row["created_at"]),
        recovered_at=cast(datetime | None, row["recovered_at"]),
        deleted_at=cast(datetime | None, row["deleted_at"]),
    )
# Keep schema terminology available to callers that use the table name.
AppUserRecord = AccountRecord
