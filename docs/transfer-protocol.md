# Transfer protocol

## Scope

This document specifies protocol version 1. Signaling messages travel through FastAPI. Encrypted transfer frames travel through an ordered WebRTC DataChannel. A relay does not change the cryptographic protocol.

The words MUST, MUST NOT, SHOULD, and MAY describe requirements that tests can enforce.

## Encodings

- Identifiers are lowercase UUID strings unless a field says otherwise.
- Binary values in JSON use unpadded base64url.
- Signed JSON uses RFC 8785 JSON Canonicalization Scheme and UTF-8.
- Public EC keys use DER SubjectPublicKeyInfo before base64url encoding.
- ECDSA signatures use the fixed-width 64-byte `r || s` P1363 form.
- Integers covered by signatures are JSON integers within JavaScript's safe integer range.
- Timestamps use integer Unix milliseconds.

Parsers MUST reject duplicate JSON keys, non-canonical signed input, invalid base64url, extra fields in a signed structure, expired messages, and unsupported versions.

## Cryptographic suite

| Purpose | Algorithm |
| --- | --- |
| Device signatures | ECDSA P-256 with SHA-256 |
| Ephemeral agreement | ECDH P-256 |
| Key derivation | HKDF-SHA-256 |
| Frame encryption | AES-256-GCM |
| File digest and fingerprints | SHA-256 |
| Random values | Web Crypto secure random source |

Each transfer uses fresh ECDH key pairs on both devices. The implementation drops references to ephemeral private keys and derived keys when a transfer reaches a terminal state.

## Transfer identifiers and state

FastAPI creates a random `transfer_id` after authorizing a sender and recipient on the same account. The server state follows this sequence:

```text
offered -> negotiating -> connected -> metadata_ready -> accepted -> transferring -> completed
       \-> rejected
       \-> expired
       \-> cancelled
       \-> failed
```

Only valid transitions are accepted. Terminal states cannot return to an active state. A reconnect creates a new transfer rather than reusing the identifier or cryptographic material.

## Transfer offer and pre-accept metadata

The initial notification contains:

```json
{
    "v": 1,
    "transfer_id": "uuid",
    "sender_device_id": "uuid",
    "recipient_device_id": "uuid",
    "file_name": "example.bin",
    "media_type": "application/octet-stream",
    "byte_count": 0,
    "created_at": 0,
    "expires_at": 0
}
```

The sender selects the file after the peer connection is ready and before it sends this offer. The recipient receives the file name, MIME type, and byte count as plain text before accepting or rejecting. The server forwards these fields only to the intended recipient and does not store them. The sender signs the canonical offer metadata with its registered device key; the recipient verifies that signature before displaying it.

The metadata is not encrypted because the recipient needs it before the encrypted file transfer begins. It is not a security verdict: the receiver must treat the name and MIME type as untrusted hints and must not automatically preview or open the file.

## Authenticated handshake

### Sender offer core

When the transfer starts, the sender creates an ephemeral ECDH key pair and a 32-byte random nonce. The recipient responds automatically to establish the authenticated connection; acceptance controls file-byte delivery, not connection setup. The sender constructs:

```json
{
    "v": 1,
    "type": "handshake_offer",
    "transfer_id": "uuid",
    "account_epoch": 1,
    "sender_device_id": "uuid",
    "recipient_device_id": "uuid",
    "sender_ephemeral_spki": "base64url",
    "sender_nonce": "base64url",
    "issued_at": 0,
    "expires_at": 0
}
```

The sender signs the canonical bytes of this object with its device signing key. The signature is transported in a wrapper and is not included inside the signed object.

The receiver checks the transfer state, identifiers, epoch, expiry, and sender device status. It fetches the sender public key from the authenticated device directory and verifies the signature before generating its answer.

### Receiver answer core

The receiver creates its own ephemeral ECDH key pair and 32-byte nonce. It constructs:

```json
{
    "v": 1,
    "type": "handshake_answer",
    "transfer_id": "uuid",
    "account_epoch": 1,
    "sender_device_id": "uuid",
    "recipient_device_id": "uuid",
    "offer_hash": "base64url",
    "recipient_ephemeral_spki": "base64url",
    "recipient_nonce": "base64url",
    "issued_at": 0,
    "expires_at": 0
}
```

`offer_hash` is SHA-256 over the canonical sender offer core. The receiver signs the answer core with its device signing key. The sender performs the corresponding checks before accepting the answer.

### Transcript

Both peers calculate:

```text
offer_bytes = JCS_UTF8(sender_offer_core)
answer_bytes = JCS_UTF8(receiver_answer_core)

transcript_hash = SHA-256(
    UTF8("secure-transfer/v1/transcript") || 0x00 ||
    offer_bytes || 0x00 || answer_bytes
)
```

Each side computes the same ECDH shared secret using its private ephemeral key and the other side's public ephemeral key. Invalid points and import failures abort the transfer.

### Derived material

HKDF-Extract uses `transcript_hash` as the salt and the ECDH output as input key material. HKDF-Expand uses separate ASCII labels prefixed with `secure-transfer/v1/`.

| Label suffix | Length | Use |
| --- | ---: | --- |
| `s2r-key` | 32 bytes | Sender-to-receiver AES key |
| `r2s-key` | 32 bytes | Receiver-to-sender AES key |
| `s2r-nonce-prefix` | 4 bytes | Sender nonce prefix |
| `r2s-nonce-prefix` | 4 bytes | Receiver nonce prefix |
| `confirmation` | 32 bytes | Handshake confirmation value |

The first encrypted message in each direction contains a confirmation derived from the transcript. A mismatch aborts before file data is processed.

## Frame format

The DataChannel carries binary frames. A frame has a bounded header followed by AES-GCM ciphertext and its tag. The authenticated header contains:

- protocol version
- transfer identifier
- direction
- frame type
- unsigned 64-bit counter
- plaintext length

The canonical header bytes are AES-GCM additional authenticated data. The nonce is:

```text
direction_nonce_prefix[4] || uint64_be(counter)[8]
```

Counters start at zero in each direction and increase by one. A sender MUST NOT reuse or decrement a counter. A receiver MUST reject duplicates, gaps that violate the ordered stream, wraparound, and a counter inconsistent with the frame type.

Frame types in version 1 are:

| Type | Direction | Purpose |
| --- | --- | --- |
| `confirm` | both | Transcript confirmation |
| `manifest` | sender to receiver | File metadata |
| `chunk` | sender to receiver | File bytes |
| `complete` | sender to receiver | Final digest and signature |
| `receipt` | receiver to sender | Verified completion |
| `cancel` | both | Authenticated cancellation reason |
| `error` | both | Bounded protocol error code |

Error and cancellation payloads use enumerated codes. They do not carry stack traces or arbitrary remote text.

## Manifest

The encrypted manifest contains:

```json
{
    "file_name": "example.bin",
    "media_type": "application/octet-stream",
    "byte_count": 0,
    "chunk_size": 65536
}
```

The receiver validates lengths and displays the values as plain text. A media type is a hint and does not control automatic rendering. File names are stripped of path components and characters that are unsafe for the target download mechanism.

The sender chooses a chunk size no larger than 64 KiB and no larger than the negotiated SCTP message size after frame overhead. A smaller runtime value is valid and is recorded in the manifest.

## File chunks and backpressure

The sender reads a slice, updates an incremental SHA-256 digest, encrypts the slice, and writes one frame. It pauses when `RTCDataChannel.bufferedAmount` crosses a configured high watermark and resumes after `bufferedamountlow`.

The receiver decrypts each frame, checks the counter and expected size, updates its own digest, and writes or buffers the bytes for the final download. The implementation must not read the complete 250 MB input into memory before transmission. Browser-specific output buffering limits are part of interoperability testing.

The plaintext length of every non-final chunk must equal the negotiated chunk size. The last chunk may be shorter. The sum must match the manifest byte count.

## Completion

After the last chunk, the sender constructs:

```json
{
    "v": 1,
    "type": "file_complete",
    "transfer_id": "uuid",
    "byte_count": 0,
    "chunk_count": 0,
    "sha256": "base64url",
    "transcript_hash": "base64url"
}
```

The sender signs the canonical object with its long-lived device key and sends the object and signature inside the encrypted `complete` frame.

The receiver verifies the signature, byte count, chunk count, transcript hash, and locally calculated file digest. It exposes the download only after every check passes. It then returns an encrypted receipt containing the transfer identifier, digest, and status.

## Signaling messages

FastAPI forwards bounded SDP and ICE messages only between the two devices named by an active transfer. Candidates received before the peer description is ready may be queued up to a fixed count. Excess candidates or oversized SDP fail the negotiation.

The backend may read signaling fields needed for routing and abuse prevention. It does not assert that SDP is secret. Signed cryptographic handshake messages remain opaque to backend modification because the peers verify them.

## TURN credentials

FastAPI issues TURN credentials only for an authenticated transfer between two active devices. Credentials have a short TTL, are scoped as narrowly as Cloudflare permits, and are rate limited per account, device, transfer, and network source.

The client includes STUN and TURN candidates according to browser ICE behavior. A test mode can force relay-only ICE so the fallback path is exercised before release.

## Failure handling

Any signature failure, GCM authentication failure, digest mismatch, invalid state transition, replay, counter error, or size violation terminates the transfer. The receiver deletes partial output where the browser API permits it and never presents it as a completed file.

Peers report a small terminal error code to FastAPI. Logs may record the code, device identifiers, and transfer identifier. They do not record cryptographic keys, file metadata, ciphertext frames, SDP bodies, or ICE candidates.

## Protocol invariants

Tests must demonstrate these statements:

1. A transfer identifier is used for one handshake only.
2. Every transfer has fresh ECDH private keys and nonces.
3. Both device signatures bind the same account epoch and peer identities.
4. Every AES-GCM key and nonce pair is unique.
5. File metadata is unavailable before the encrypted channel is confirmed.
6. A completed download has a verified sender signature, byte count, and SHA-256 digest.
7. A device from another account cannot receive signaling or TURN credentials for the transfer.
