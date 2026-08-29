# Threat model

## Security claim

During normal operation, a file is encrypted in the sender's browser and decrypted in the receiver's browser. The application backend and relay do not receive the plaintext file or its encrypted manifest key.

This claim assumes that the web host serves the documented client code. It does not cover a malicious host, malicious browser extension, compromised endpoint, or recipient who intentionally shares the file.

## Protected assets

- plaintext file contents and encrypted manifest metadata
- long-lived device signing keys
- ephemeral transfer private keys and derived AES keys
- application session and CSRF tokens
- Supabase, database, TURN, and SMTP credentials
- device approval and recovery authority
- account email addresses and device records
- integrity of the public-key directory and client application

## Trusted systems

The following systems are trusted for version 1:

- the sender and receiver operating systems and browsers
- the JavaScript and same-origin gateway distributed through Cloudflare Pages
- FastAPI on Cloud Run, including authorization and the device public-key directory
- Supabase Auth as proof of email control
- the user's email account during bootstrap and recovery
- Supabase PostgreSQL for integrity and availability of application records

Cloudflare TURN is not trusted with file plaintext. Network providers are not trusted with plaintext. The protocol relies on TLS and application encryption when communicating through them.

## Adversaries

### Unauthenticated Internet attacker

The attacker can call public endpoints, create connections, guess identifiers, submit malformed input, and consume bandwidth. They may distribute requests across several IP addresses.

### Network observer or active network attacker

The attacker can observe, delay, drop, replay, or modify network traffic but cannot break correctly configured TLS, DTLS, ECDSA, ECDH, HKDF, AES-GCM, or SHA-256.

### Malicious or compromised relay

The relay can record packets, IP addresses, timing, and volume. It may drop, delay, duplicate, or reorder traffic.

### Compromised account email

The attacker can receive a recovery OTP. Because version 1 has no MFA or recovery code, email control is sufficient to recover the account and invalidate existing sessions.

### Malicious peer device

A trusted device may send deceptive metadata, malformed ciphertext, or a harmful file. It may also decline, interrupt, or falsely report a transfer.

### Database reader

The attacker can read application tables but cannot modify client code or obtain backend environment secrets. Public keys, session hashes, account metadata, and audit events are exposed in this scenario. File plaintext and private keys should not be present.

### Compromised web host or backend

This attacker can replace JavaScript, alter the public-key directory, or change authorization behavior. Version 1 does not claim confidentiality against this attacker. The limitation must remain visible in the README and user-facing security explanation.

## Threats and controls

| Threat | Controls | Remaining exposure |
| --- | --- | --- |
| File interception | TLS, WebRTC DTLS, authenticated ECDH, AES-256-GCM | Traffic timing and volume remain visible |
| Peer-key substitution in transit | Signed handshake, TLS, trusted device directory | A malicious backend can substitute code or directory entries |
| Replay of a handshake | Random nonces, transfer identifiers, expiry, one-time server state | A compromised endpoint can create a fresh valid handshake |
| Repeated AES-GCM nonce | Derived direction-specific keys, fixed prefix, monotonic 64-bit counter, duplicate rejection | Implementation defects remain possible and require tests |
| Corrupt or truncated file | Per-frame GCM tag, counters, final byte count, SHA-256 digest, signed completion | A malicious sender can knowingly send a harmful but internally consistent file |
| Session theft from script | `HttpOnly` cookie, CSP, output encoding, no token in local storage | A successful XSS can act through the user's session even without reading the cookie |
| CSRF | Host-only `SameSite=Lax` cookie, exact Origin check, session-bound CSRF token | A compromised allowed origin defeats these controls |
| WebSocket hijacking | Exact Origin check and single-use authenticated ticket | Stolen application sessions remain useful until revoked |
| Device enrollment abuse | Signed approval bound to new key fingerprint, short expiry, visible code, attempt limit | An inattentive user may approve the wrong request |
| Email OTP abuse | Generic responses, per-IP and per-account limits, Supabase limits, CAPTCHA when needed | Distributed abuse and email flooding cannot be eliminated |
| User enumeration | Same response and comparable work for existing and unknown emails | SMTP side channels and timing need measurement |
| Cross-account access | Server-side ownership checks on every object and socket message | Authorization bugs remain a primary test target |
| TURN theft | Credentials issued after acceptance, short TTL, transfer binding, issuance quotas | A stolen credential can be used until expiry |
| Resource exhaustion | Bounded bodies, connection quotas, timeouts, backpressure, file limit, cleanup jobs | A small single instance can still be saturated |
| SQL injection | Parameterized queries and constrained models | Unsafe raw SQL added later could reintroduce the issue |
| Dependency compromise | Lockfiles, pinned releases, update review, CSP, minimal browser dependencies | A trusted dependency can still publish malicious code |
| Secret disclosure | Environment secret stores, log redaction, secret scanning, separate keys by environment | Operator or hosting-account compromise remains in scope operationally |

## File-specific risks

The receiver controls whether to accept a transfer and must choose where to save it. The application treats the name and MIME type as hints. It sanitizes display text, does not create executable previews, and does not automatically open the file.

The server cannot scan for malware because it never receives the file. The UI must say this plainly. A successful integrity check proves that the received bytes match what the authenticated sender transmitted. It does not prove that the file is safe.

## Denial of service

The backend applies separate limits to OTP requests, challenge issuance, pairing requests, WebSocket connections, transfer offers, signaling messages, and TURN credentials. Limits use both account and network signals where practical. Error messages do not reveal whether an email or device exists.

Message bodies have small fixed limits. WebSocket queues are bounded, stale offers expire after 10 minutes, and an inactive socket is closed after missed heartbeats. A user cannot obtain TURN credentials for an unaccepted or cross-account transfer.

Cloudflare protects the public Pages origin and its narrowly scoped gateway. The Cloud Run `run.app` upstream remains Internet reachable for the gateway and authenticated operations probe, so an attacker can bypass the Pages edge and call it directly. FastAPI and Cloud Run therefore retain API-level authentication, exact Origin checks, CSRF controls, bounded inputs, rate limits, and one-instance capacity limits. The maximum-instance setting bounds scale and cost exposure but can make saturation easier; it is not treated as denial-of-service protection.

## Privacy limits

Infrastructure providers may observe:

- account and recovery email delivery
- device and session activity
- source IP addresses and user agents
- transfer start and completion times
- direct or relayed connection metadata
- relayed traffic volume

The design does not hide account relationships, online presence, or traffic patterns. Audit events expire after 30 days unless an active investigation requires preservation.

## Out of scope

- endpoint malware, hostile extensions, and physical device access
- a malicious or compelled service operator
- cryptographic breaks in the selected standard algorithms
- phishing that convinces a user to approve a device
- recipient misuse after decryption
- anonymity and traffic-analysis resistance
- reliable operation during provider outages

## Review triggers

Review this threat model before adding cross-account sharing, offline storage, resumable transfers, previews, native clients, MFA, organization accounts, background operation, or more than one backend instance. Each feature changes at least one trust boundary.
