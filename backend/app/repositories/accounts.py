"""Repository operations for application accounts."""

from __future__ import annotations

from uuid import UUID

from .base import RepositoryDatabase, first_row, required_row
from .models import AccountRecord, account_from_row

_ACCOUNT_COLUMNS = """
    id,
    supabase_user_id,
    email_normalized,
    device_epoch,
    created_at,
    recovered_at,
    deleted_at
"""


class AccountRepository:
    """Persist and retrieve account records without exposing SQL to callers."""

    def __init__(self, database: RepositoryDatabase) -> None:
        self._database = database

    async def get_by_id(self, account_id: UUID) -> AccountRecord | None:
        """Return an active account by its internal identifier."""

        rows = await self._database.fetch(
            f"""SELECT {_ACCOUNT_COLUMNS}
            FROM private.app_users
            WHERE id = $1 AND deleted_at IS NULL""",
            account_id,
        )
        row = first_row(rows)
        return None if row is None else account_from_row(row)

    async def get_by_supabase_user_id(
        self,
        supabase_user_id: UUID,
    ) -> AccountRecord | None:
        """Return an active account linked to a verified Supabase identity."""

        rows = await self._database.fetch(
            f"""SELECT {_ACCOUNT_COLUMNS}
            FROM private.app_users
            WHERE supabase_user_id = $1 AND deleted_at IS NULL""",
            supabase_user_id,
        )
        row = first_row(rows)
        return None if row is None else account_from_row(row)

    async def get_by_email(self, email_normalized: str) -> AccountRecord | None:
        """Return an active account by its already-normalized email."""

        rows = await self._database.fetch(
            f"""SELECT {_ACCOUNT_COLUMNS}
            FROM private.app_users
            WHERE email_normalized = $1 AND deleted_at IS NULL""",
            email_normalized,
        )
        row = first_row(rows)
        return None if row is None else account_from_row(row)

    async def create(
        self,
        supabase_user_id: UUID,
        email_normalized: str,
    ) -> AccountRecord:
        """Create and return an account linked to a verified identity."""

        rows = await self._database.fetch(
            f"""INSERT INTO private.app_users (supabase_user_id, email_normalized)
            VALUES ($1, $2)
            RETURNING {_ACCOUNT_COLUMNS}""",
            supabase_user_id,
            email_normalized,
        )
        return account_from_row(required_row(rows))


# ``AppUserRepository`` mirrors the table name for callers that use schema terms.
AppUserRepository = AccountRepository
