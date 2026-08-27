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


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    """One trusted device registered to an application account."""

    id: UUID
    user_id: UUID
    epoch: int
    label: str
    signing_public_key_spki: bytes
    fingerprint: bytes
    status: str
    created_at: datetime
    last_seen_at: datetime
    revoked_at: datetime | None
    approved_by_device_id: UUID | None


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """One opaque application session bound to an account and device."""

    id: UUID
    user_id: UUID
    device_id: UUID
    token_hash: bytes
    csrf_hash: bytes
    epoch: int
    created_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None


@dataclass(frozen=True, slots=True)
class DeviceChallengeRecord:
    """One short-lived, one-time challenge issued to a trusted device."""

    id: UUID
    device_id: UUID
    nonce_hash: bytes
    origin: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None
    attempt_count: int


@dataclass(frozen=True, slots=True)
class PairingRequestRecord:
    """One account-owned request to enroll a new trusted device."""

    id: UUID
    user_id: UUID
    requested_public_key_spki: bytes
    requested_fingerprint: bytes
    requested_label: str
    request_nonce: bytes
    comparison_code_hash: bytes
    status: str
    attempt_count: int
    approved_by_device_id: UUID | None
    approval_signature: bytes | None
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None


@dataclass(frozen=True, slots=True)
class WebSocketTicketRecord:
    """One short-lived, single-use ticket bound to an application session."""

    id: UUID
    session_id: UUID
    token_hash: bytes
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None


@dataclass(frozen=True, slots=True)
class TransferRequestRecord:
    """One account-owned transfer offer and its control-plane state."""

    id: UUID
    user_id: UUID
    sender_device_id: UUID
    recipient_device_id: UUID
    protocol_version: int
    status: str
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None
    completed_at: datetime | None
    failure_code: str | None
    relay_used: bool


@dataclass(frozen=True, slots=True)
class SecurityEventRecord:
    """One short-lived security audit event."""

    id: UUID
    user_id: UUID | None
    device_id: UUID | None
    event_type: str
    outcome: str
    network_fingerprint: bytes | None
    details: Mapping[str, object]
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RateLimitBucketRecord:
    """One persistent, HMAC-keyed rate-limit bucket."""

    scope: str
    bucket_key: bytes
    window_started_at: datetime
    window_expires_at: datetime
    request_count: int


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


def device_from_row(row: Mapping[str, object]) -> DeviceRecord:
    """Convert a database row into an immutable device record."""

    return DeviceRecord(
        id=cast(UUID, row["id"]),
        user_id=cast(UUID, row["user_id"]),
        epoch=cast(int, row["epoch"]),
        label=cast(str, row["label"]),
        signing_public_key_spki=cast(bytes, row["signing_public_key_spki"]),
        fingerprint=cast(bytes, row["fingerprint"]),
        status=cast(str, row["status"]),
        created_at=cast(datetime, row["created_at"]),
        last_seen_at=cast(datetime, row["last_seen_at"]),
        revoked_at=cast(datetime | None, row["revoked_at"]),
        approved_by_device_id=cast(UUID | None, row["approved_by_device_id"]),
    )


def session_from_row(row: Mapping[str, object]) -> SessionRecord:
    """Convert a database row into an immutable session record."""

    return SessionRecord(
        id=cast(UUID, row["id"]),
        user_id=cast(UUID, row["user_id"]),
        device_id=cast(UUID, row["device_id"]),
        token_hash=cast(bytes, row["token_hash"]),
        csrf_hash=cast(bytes, row["csrf_hash"]),
        epoch=cast(int, row["epoch"]),
        created_at=cast(datetime, row["created_at"]),
        last_seen_at=cast(datetime, row["last_seen_at"]),
        idle_expires_at=cast(datetime, row["idle_expires_at"]),
        absolute_expires_at=cast(datetime, row["absolute_expires_at"]),
        revoked_at=cast(datetime | None, row["revoked_at"]),
        revocation_reason=cast(str | None, row["revocation_reason"]),
    )


def device_challenge_from_row(row: Mapping[str, object]) -> DeviceChallengeRecord:
    """Convert a database row into an immutable device challenge record."""

    return DeviceChallengeRecord(
        id=cast(UUID, row["id"]),
        device_id=cast(UUID, row["device_id"]),
        nonce_hash=cast(bytes, row["nonce_hash"]),
        origin=cast(str, row["origin"]),
        created_at=cast(datetime, row["created_at"]),
        expires_at=cast(datetime, row["expires_at"]),
        consumed_at=cast(datetime | None, row["consumed_at"]),
        attempt_count=cast(int, row["attempt_count"]),
    )


def pairing_request_from_row(row: Mapping[str, object]) -> PairingRequestRecord:
    """Convert a database row into an immutable pairing request record."""

    return PairingRequestRecord(
        id=cast(UUID, row["id"]),
        user_id=cast(UUID, row["user_id"]),
        requested_public_key_spki=cast(bytes, row["requested_public_key_spki"]),
        requested_fingerprint=cast(bytes, row["requested_fingerprint"]),
        requested_label=cast(str, row["requested_label"]),
        request_nonce=cast(bytes, row["request_nonce"]),
        comparison_code_hash=cast(bytes, row["comparison_code_hash"]),
        status=cast(str, row["status"]),
        attempt_count=cast(int, row["attempt_count"]),
        approved_by_device_id=cast(UUID | None, row["approved_by_device_id"]),
        approval_signature=cast(bytes | None, row["approval_signature"]),
        created_at=cast(datetime, row["created_at"]),
        expires_at=cast(datetime, row["expires_at"]),
        consumed_at=cast(datetime | None, row["consumed_at"]),
    )


def websocket_ticket_from_row(row: Mapping[str, object]) -> WebSocketTicketRecord:
    """Convert a database row into an immutable WebSocket ticket record."""

    return WebSocketTicketRecord(
        id=cast(UUID, row["id"]),
        session_id=cast(UUID, row["session_id"]),
        token_hash=cast(bytes, row["token_hash"]),
        created_at=cast(datetime, row["created_at"]),
        expires_at=cast(datetime, row["expires_at"]),
        consumed_at=cast(datetime | None, row["consumed_at"]),
    )


def transfer_request_from_row(row: Mapping[str, object]) -> TransferRequestRecord:
    """Convert a transfer request row into an immutable record."""

    return TransferRequestRecord(
        id=cast(UUID, row["id"]),
        user_id=cast(UUID, row["user_id"]),
        sender_device_id=cast(UUID, row["sender_device_id"]),
        recipient_device_id=cast(UUID, row["recipient_device_id"]),
        protocol_version=cast(int, row["protocol_version"]),
        status=cast(str, row["status"]),
        created_at=cast(datetime, row["created_at"]),
        expires_at=cast(datetime, row["expires_at"]),
        accepted_at=cast(datetime | None, row["accepted_at"]),
        completed_at=cast(datetime | None, row["completed_at"]),
        failure_code=cast(str | None, row["failure_code"]),
        relay_used=cast(bool, row["relay_used"]),
    )


def security_event_from_row(row: Mapping[str, object]) -> SecurityEventRecord:
    """Convert a security event row into an immutable record."""

    return SecurityEventRecord(
        id=cast(UUID, row["id"]),
        user_id=cast(UUID | None, row["user_id"]),
        device_id=cast(UUID | None, row["device_id"]),
        event_type=cast(str, row["event_type"]),
        outcome=cast(str, row["outcome"]),
        network_fingerprint=cast(bytes | None, row["network_fingerprint"]),
        details=cast(Mapping[str, object], row["details"]),
        created_at=cast(datetime, row["created_at"]),
        expires_at=cast(datetime, row["expires_at"]),
    )


def rate_limit_bucket_from_row(row: Mapping[str, object]) -> RateLimitBucketRecord:
    """Convert a rate-limit bucket row into an immutable record."""

    return RateLimitBucketRecord(
        scope=cast(str, row["scope"]),
        bucket_key=cast(bytes, row["bucket_key"]),
        window_started_at=cast(datetime, row["window_started_at"]),
        window_expires_at=cast(datetime, row["window_expires_at"]),
        request_count=cast(int, row["request_count"]),
    )


# Keep schema terminology available to callers that use the table name.
AppUserRecord = AccountRecord
