"""Cryptographic helpers for long-lived browser device identities.

The browser uses Web Crypto's ECDSA P-256 implementation.  Web Crypto
transports signatures as the fixed-width IEEE P1363 ``r || s`` form while
``cryptography`` verifies the DER encoded ECDSA form, so the conversion is
kept at this boundary and the rest of the application deals in P1363 bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

from .repositories.models import (
    AccountRecord,
    DeviceChallengeRecord,
    DeviceRecord,
    PairingRequestRecord,
)

DEVICE_PROTOCOL_VERSION = 1
DEVICE_CHALLENGE_VERSION = 1
PAIRING_APPROVAL_VERSION = 1
PAIRING_ENROLLMENT_VERSION = 1
DEVICE_SIGNATURE_BYTES = 64
SHA256_BYTES = hashlib.sha256().digest_size

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class DeviceCryptoError(ValueError):
    """Raised when a device key or signature is not valid for this protocol."""


def encode_base64url(value: bytes) -> str:
    """Encode bytes as unpadded base64url for JSON transport."""

    return base64.urlsafe_b64encode(bytes(value)).decode("ascii").rstrip("=")


def decode_base64url(value: str, *, maximum_bytes: int = 4096) -> bytes:
    """Decode strict unpadded (or safely padded) base64url input."""

    if not isinstance(value, str) or not value or len(value) > maximum_bytes * 2:
        raise DeviceCryptoError("invalid base64url value")
    if not _BASE64URL_RE.fullmatch(value):
        raise DeviceCryptoError("invalid base64url value")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise DeviceCryptoError("invalid base64url value") from error
    if not decoded or len(decoded) > maximum_bytes:
        raise DeviceCryptoError("invalid base64url value")
    return decoded


def normalize_timestamp(value: datetime) -> str:
    """Represent a timestamp in the canonical JSON form shared with the client."""

    if value.tzinfo is None:
        raise DeviceCryptoError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_json_bytes(value: object) -> bytes:
    """Serialize a JSON value deterministically for signature verification."""

    def normalize(item: object) -> object:
        if item is None or isinstance(item, str | bool | int):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise DeviceCryptoError("non-finite JSON numbers are not supported")
            return item
        if isinstance(item, Mapping):
            normalized: dict[str, object] = {}
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise DeviceCryptoError("JSON object keys must be strings")
                normalized[key] = normalize(nested)
            return normalized
        if isinstance(item, Sequence) and not isinstance(item, bytes | bytearray | str):
            return [normalize(nested) for nested in item]
        raise DeviceCryptoError("unsupported JSON value")

    try:
        encoded = json.dumps(
            normalize(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise DeviceCryptoError("value cannot be canonicalized") from error
    return encoded.encode("utf-8")


def challenge_payload(
    challenge: DeviceChallengeRecord,
    account: object,
    device: DeviceRecord,
    *,
    nonce: bytes,
) -> dict[str, object]:
    """Build the signed returning-device challenge object."""

    account_id = getattr(account, "id", None)
    account_epoch = getattr(account, "device_epoch", None)
    if account_id is None or account_epoch is None:
        raise DeviceCryptoError("account record is incomplete")
    if challenge.device_id != device.id:
        raise DeviceCryptoError("challenge and device do not match")
    if len(nonce) != 32:
        raise DeviceCryptoError("challenge nonce must contain 256 bits")
    return {
        "account_device_epoch": account_epoch,
        "account_id": str(account_id),
        "challenge_id": str(challenge.id),
        "challenge_version": DEVICE_CHALLENGE_VERSION,
        "device_id": str(device.id),
        "expires_at": normalize_timestamp(challenge.expires_at),
        "issued_at": normalize_timestamp(challenge.created_at),
        "nonce": encode_base64url(nonce),
        "origin": challenge.origin,
        "protocol_version": DEVICE_PROTOCOL_VERSION,
    }


def registration_payload(
    *,
    challenge_id: str,
    account_id: str,
    device_id: str,
    epoch: int,
    nonce: bytes,
    origin: str,
    issued_at: datetime,
    expires_at: datetime,
    fingerprint: bytes,
    recovery: bool = False,
) -> dict[str, object]:
    """Build the signed first-registration/recovery challenge object."""

    if len(nonce) != 32:
        raise DeviceCryptoError("challenge nonce must contain 256 bits")
    if len(fingerprint) != SHA256_BYTES:
        raise DeviceCryptoError("device fingerprint must be a SHA-256 digest")
    return {
        "account_device_epoch": epoch,
        "account_id": account_id,
        "challenge_id": challenge_id,
        "challenge_version": DEVICE_CHALLENGE_VERSION,
        "device_fingerprint": encode_base64url(fingerprint),
        "device_id": device_id,
        "expires_at": normalize_timestamp(expires_at),
        "issued_at": normalize_timestamp(issued_at),
        "nonce": encode_base64url(nonce),
        "origin": origin,
        "protocol_version": DEVICE_PROTOCOL_VERSION,
        "recovery": recovery,
    }


def pairing_approval_payload(
    request: PairingRequestRecord,
    account: AccountRecord,
    approving_device: DeviceRecord,
    *,
    approval_nonce: bytes,
) -> dict[str, object]:
    """Build the canonical statement signed by a trusted approving device."""

    if request.user_id != account.id or approving_device.user_id != account.id:
        raise DeviceCryptoError("pairing records do not belong to the account")
    if approving_device.epoch != account.device_epoch:
        raise DeviceCryptoError("approving device is from an old epoch")
    if len(request.request_nonce) != 32:
        raise DeviceCryptoError("pairing request nonce must contain 256 bits")
    if len(request.requested_fingerprint) != SHA256_BYTES:
        raise DeviceCryptoError("requested fingerprint must be a SHA-256 digest")
    if len(approval_nonce) != 32:
        raise DeviceCryptoError("approval nonce must contain 256 bits")
    return {
        "account_device_epoch": account.device_epoch,
        "account_id": str(account.id),
        "approval_nonce": encode_base64url(approval_nonce),
        "expires_at": normalize_timestamp(request.expires_at),
        "pairing_approval_version": PAIRING_APPROVAL_VERSION,
        "pairing_request_id": str(request.id),
        "protocol_version": DEVICE_PROTOCOL_VERSION,
        "requested_fingerprint": encode_base64url(request.requested_fingerprint),
        "request_nonce": encode_base64url(request.request_nonce),
    }


def pairing_approval_message(payload: Mapping[str, object]) -> bytes:
    """Add a pairing-specific domain separator to an approval statement."""

    return b"e2e-secure-file-transfer/pairing-approval/v1\x00" + canonical_json_bytes(payload)


def pairing_enrollment_payload(
    request: PairingRequestRecord,
    account: AccountRecord,
    *,
    approval_nonce: bytes,
) -> dict[str, object]:
    """Build the proof-of-possession statement for an approved pairing."""

    if request.user_id != account.id:
        raise DeviceCryptoError("pairing request does not belong to the account")
    if account.device_epoch < 0:
        raise DeviceCryptoError("account epoch is invalid")
    if len(request.request_nonce) != 32:
        raise DeviceCryptoError("pairing request nonce must contain 256 bits")
    if len(request.requested_fingerprint) != SHA256_BYTES:
        raise DeviceCryptoError("requested fingerprint must be a SHA-256 digest")
    if len(approval_nonce) != 32:
        raise DeviceCryptoError("approval nonce must contain 256 bits")
    return {
        "account_device_epoch": account.device_epoch,
        "account_id": str(account.id),
        "approval_nonce": encode_base64url(approval_nonce),
        "expires_at": normalize_timestamp(request.expires_at),
        "pairing_enrollment_version": PAIRING_ENROLLMENT_VERSION,
        "pairing_request_id": str(request.id),
        "protocol_version": DEVICE_PROTOCOL_VERSION,
        "requested_fingerprint": encode_base64url(request.requested_fingerprint),
        "request_nonce": encode_base64url(request.request_nonce),
    }


def pairing_enrollment_message(payload: Mapping[str, object]) -> bytes:
    """Add a domain separator to the new-device possession statement."""

    return b"e2e-secure-file-transfer/pairing-enrollment/v1\x00" + canonical_json_bytes(payload)


def signed_message(payload: Mapping[str, object]) -> bytes:
    """Add a domain separator to a canonical challenge before signing."""

    return b"e2e-secure-file-transfer/device-auth/v1\x00" + canonical_json_bytes(payload)


def fingerprint_public_key(public_key_spki: bytes) -> bytes:
    """Validate a P-256 SPKI public key and return its SHA-256 fingerprint."""

    canonical = canonical_public_key(public_key_spki)
    return hashlib.sha256(canonical).digest()


def canonical_public_key(public_key_spki: bytes) -> bytes:
    """Return the canonical DER SPKI for an ECDSA P-256 public key."""

    if not isinstance(public_key_spki, bytes | bytearray):
        raise DeviceCryptoError("public key must be bytes")
    raw = bytes(public_key_spki)
    if not 1 <= len(raw) <= 1024:
        raise DeviceCryptoError("public key has an invalid length")
    try:
        key = load_der_public_key(raw)
    except (ValueError, TypeError) as error:
        raise DeviceCryptoError("public key is not valid DER") from error
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise DeviceCryptoError("public key must use ECDSA P-256")
    canonical = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if canonical != raw:
        raise DeviceCryptoError("public key is not canonical SPKI")
    return canonical


def p1363_to_der(signature: bytes) -> bytes:
    """Convert fixed-width ECDSA P1363 ``r || s`` bytes to DER."""

    if len(signature) != DEVICE_SIGNATURE_BYTES:
        raise DeviceCryptoError("ECDSA signature must be 64-byte P1363")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r <= 0 or s <= 0:
        raise DeviceCryptoError("ECDSA signature integers must be positive")
    return encode_dss_signature(r, s)


def der_to_p1363(signature: bytes) -> bytes:
    """Convert a DER ECDSA signature to fixed-width P1363 bytes."""

    try:
        r, s = decode_dss_signature(signature)
    except ValueError as error:
        raise DeviceCryptoError("invalid DER ECDSA signature") from error
    if not 0 < r < 2**256 or not 0 < s < 2**256:
        raise DeviceCryptoError("ECDSA signature integer is out of range")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_signature(public_key_spki: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a P1363 or DER ECDSA P-256 signature over ``message``."""

    try:
        canonical_key = canonical_public_key(public_key_spki)
        key = load_der_public_key(canonical_key)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            return False
        der_signature = (
            p1363_to_der(bytes(signature))
            if len(signature) == DEVICE_SIGNATURE_BYTES
            else bytes(signature)
        )
        key.verify(der_signature, message, ec.ECDSA(SHA256()))
        return True
    except (DeviceCryptoError, InvalidSignature, ValueError, TypeError):
        return False


def verify_p1363_signature(public_key_spki: bytes, signature: bytes, message: bytes) -> bool:
    """Explicit P1363-only alias used by device-auth callers and tests."""

    if len(signature) != DEVICE_SIGNATURE_BYTES:
        return False
    return verify_signature(public_key_spki, signature, message)


__all__ = [
    "DEVICE_CHALLENGE_VERSION",
    "DEVICE_PROTOCOL_VERSION",
    "DEVICE_SIGNATURE_BYTES",
    "PAIRING_APPROVAL_VERSION",
    "PAIRING_ENROLLMENT_VERSION",
    "DeviceCryptoError",
    "canonical_json_bytes",
    "canonical_public_key",
    "challenge_payload",
    "decode_base64url",
    "der_to_p1363",
    "encode_base64url",
    "fingerprint_public_key",
    "normalize_timestamp",
    "pairing_approval_message",
    "pairing_approval_payload",
    "pairing_enrollment_message",
    "pairing_enrollment_payload",
    "p1363_to_der",
    "registration_payload",
    "signed_message",
    "verify_p1363_signature",
    "verify_signature",
]
