# Project specification

## Status

This document defines the locked version 1 requirements. Implementation through Phase 10 is complete, and hosted deployment work is in progress in Phase 11. A requirement change should also update the architecture, threat model, protocol, tests, and decision log when those documents are affected.

## Problem

A user should be able to open a website on two devices, sign in to the same account, and send a file between them. The application should avoid routing the file through the application server. It should also keep the file confidential from signaling, database, and relay infrastructure during normal operation.

## Users

Version 1 has one user role. An account owner may register several trusted browsers or devices. Transfers only occur between devices on the same account.

The service targets small-scale public deployment rather than business-critical or multi-tenant operation. Controls expected of an Internet-facing application remain required, and each security claim must be testable.

## Functional requirements

### Accounts and sessions

1. A user can create or recover an account by verifying an email OTP issued through Supabase Auth.
2. The application does not accept passwords.
3. FastAPI creates an opaque application session after identity verification.
4. The browser stores the session identifier in a `Secure`, `HttpOnly`, host-only cookie.
5. A session expires after 30 days without use or 90 days after creation, whichever comes first.
6. A user can list and revoke their sessions and devices.

### Devices

1. Each trusted device has its own ECDSA P-256 signing key pair.
2. The browser creates the private key as a non-extractable Web Crypto key and stores it in IndexedDB.
3. The server stores the public key, fingerprint, status, and lifecycle timestamps.
4. A returning trusted device can authenticate by signing a fresh server challenge.
5. A new device normally requires approval from an online trusted device.
6. Email recovery revokes existing application sessions and starts a new device epoch.

### Transfers

1. The sender chooses one online device on the same account.
2. The receiver must accept the transfer before file metadata is disclosed.
3. The peers authenticate fresh ECDH keys with their device signing keys.
4. The sender encrypts the manifest and file chunks with AES-256-GCM.
5. The peers use a WebRTC DataChannel for the file.
6. The WebRTC connection attempts a direct route first and may use Cloudflare TURN.
7. The receiver checks the final byte count and SHA-256 digest before presenting the download.
8. The application never uploads the file to FastAPI, Supabase Storage, or Cloudflare storage.

### Operations

1. The API exposes health and readiness checks that do not disclose secrets.
2. Authentication, pairing, signaling, and TURN credential issuance are rate limited.
3. Security logs omit OTPs, session tokens, private keys, file names, and file contents.
4. Pending offers expire automatically.
5. Old sessions, pairing requests, and audit events are removed according to the retention schedule.

## Version 1 limits

| Limit | Value |
| --- | --- |
| File size | 250 MB maximum |
| Files per transfer | One |
| Concurrent inbound transfers per device | One |
| Transfer availability | Both pages must remain open and online |
| Pending offer lifetime | 10 minutes |
| Application session idle lifetime | 30 days |
| Application session absolute lifetime | 90 days |
| Audit event retention | 30 days |
| Official browser support | Current Chrome, Edge, and Firefox desktop |
| Best-effort support | Current Safari and foreground mobile browsers |

The exact chunk size can adapt to the negotiated WebRTC message limit. The protocol default is 64 KiB before framing overhead.

## Security requirements

- TLS protects HTTP and WebSocket traffic.
- Every WebSocket starts with a single-use ticket issued through an authenticated HTTP request.
- Unsafe HTTP methods require a valid Origin and CSRF token.
- A device key is never accepted without email recovery or a signed approval from an active trusted device.
- Signed messages use deterministic encoding and include the protocol version, device identifiers, request identifier, nonces, and expiry.
- Each AES-GCM key and nonce pair is unique.
- Parsers reject unknown protocol versions, duplicate fields, invalid encodings, replayed identifiers, expired messages, and frames that exceed their limit.
- The frontend uses a restrictive Content Security Policy and pinned dependencies.
- The backend authorizes every account-scoped operation. Authentication alone is not treated as authorization.

## Privacy requirements

The database may contain an email address, device labels, public keys, session metadata, pairing records, and minimal transfer events. It must not contain file names, file bytes, private device keys, OTP values, raw session cookies, or decrypted transfer metadata.

TURN and hosting providers can observe IP addresses, timing, and traffic volume. The protocol does not attempt to hide that metadata.

## Non-goals

Version 1 does not provide:

- transfers between different accounts
- offline delivery or server-side queues containing files
- transfer resumption after a page closes or network session is lost
- background mobile transfers
- folder synchronization
- malware scanning or automatic file opening
- password login, MFA, hardware keys, or social login
- protection from a malicious web host or compromised endpoint
- anonymity or resistance to traffic analysis
- a production uptime guarantee

## Acceptance criteria

Version 1 is complete when two supported browsers can register as devices, establish an authenticated direct or relayed WebRTC connection, transfer a 250 MB test file without reading the whole input into the sender's memory before transmission, and reject altered or replayed protocol messages.

The release must also pass the security cases in [testing-strategy.md](testing-strategy.md), deploy without repository secrets, and document any browser-specific failure found during interoperability testing.
