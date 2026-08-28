# Testing strategy

## Approach

Tests follow the boundaries in the design. Pure protocol code receives deterministic fixtures. Backend tests use disposable data and fake external adapters. Browser tests exercise the real Web Crypto and WebRTC implementations. A small set of staging tests covers hosted Supabase, SMTP, and TURN.

No test depends on a production credential or a real user's file.

## Test layers

### TypeScript unit tests

The frontend unit suite covers:

- canonical JSON encoding and rejection of unsupported values
- SPKI import, export, and fingerprint calculation
- P1363 ECDSA signature encoding
- handshake transcript construction
- HKDF labels and output lengths
- AES-GCM nonce construction and counter limits
- manifest and frame parsing with strict bounds
- transfer state transitions
- file-name sanitization and plain-text rendering
- backpressure behavior with mocked channel thresholds
- availability wrapper state transitions, retry caps, backoff/jitter bounds, and delegation to the presence client without a second reconnect loop

Cryptographic tests use fixed private test vectors committed only for testing. Production never imports those keys.

### Python unit tests

The backend suite covers:

- email normalization and generic auth responses
- session token hashing, expiry, rotation, and revocation
- CSRF and Origin checks
- device challenge verification
- pairing approval authorization and one-time consumption
- account epoch changes during recovery
- cross-account ownership rejection
- transfer state transitions and expiry
- WebSocket ticket consumption
- rate-limit buckets and cleanup
- safe log fields and error mapping
- availability router authentication, bounded readiness/probe behavior, database timeout handling, and safe failure responses

External calls use typed fakes for Supabase Auth and Cloudflare TURN.

### Shared protocol fixtures

TypeScript produces and consumes the same fixtures as Python for messages the backend verifies. Fixtures include:

- canonical offer and answer bytes
- public-key fingerprints
- valid and invalid ECDSA signatures
- transcript hashes
- ECDH and HKDF outputs
- direction-specific keys and nonce prefixes
- encrypted frames and expected plaintext
- malformed, expired, replayed, and oversized messages

A change that makes either implementation disagree with a version 1 fixture requires a protocol-version decision rather than silently replacing the fixture.

### Database tests

Database tests apply every migration to an empty instance and verify:

- required constraints and indexes exist
- a cross-account transfer cannot be inserted
- a pairing request cannot be consumed twice
- session and device revocation are atomic
- cleanup queries delete only expired records
- the runtime role has its intended grants
- `anon`, `authenticated`, and `PUBLIC` cannot access private application tables
- row-level security is enabled on any table placed in an exposed schema

Supabase database advisors run before a release migration is accepted.

### API integration tests

Integration tests start FastAPI with a disposable database and fake Auth and TURN adapters. They cover complete flows instead of isolated routes:

1. bootstrap, device registration, session use, and logout
2. returning-device challenge login
3. trusted-device pairing and rejection
4. email recovery with epoch rotation
5. presence, offer, acceptance, signaling, and completion
6. cancellation, expiry, and process restart behavior
7. concurrent requests attempting to consume one challenge or pairing request
8. availability wake/readiness, authenticated database-backed probe, and terminal failure behavior

Every account-scoped endpoint receives an ownership-negative test. Identifiers from a second account must return the same safe failure regardless of whether the target exists.

### Availability module tests

The frontend, backend, and operations availability modules are tested as separate boundaries. Tests verify that:

- the frontend sends a bounded HTTP wake/readiness request before opening WSS and then delegates reconnects to the existing presence client
- capped retries use bounded backoff and jitter, reach a terminal failure state, and never remain pending forever
- readiness and probe routes return only safe status values, reject unauthenticated probes, and do not disclose database or service diagnostics
- the probe performs a genuine database-backed end-to-end check with a short timeout, reports failures, and keeps its credentials in host secret stores
- the intended scheduler can run the provider-neutral probe three times per day by default, with a configurable cadence, without changing transfer or presence behavior

### Browser tests

Playwright runs at least two isolated browser contexts. Supported-browser runs cover Chrome, Edge, and Firefox where the test environment provides them. Safari behavior is checked separately on a compatible host.

Browser cases include:

- first device registration and IndexedDB persistence
- session restoration after a page reload
- loss of IndexedDB and the resulting pairing requirement
- two-device code comparison and approval
- direct WebRTC transfer of empty, small, odd-sized, and maximum-size files
- forced TURN relay transfer
- cancellation by either peer
- network interruption and clear failure reporting
- tampered handshake signature
- tampered encrypted chunk and final digest
- duplicate or skipped frame counter
- malicious file name and MIME type
- receiver rejection before metadata disclosure
- backend cold-start wake, bounded availability states, and WebSocket reconnect after restart

Mobile checks keep the page in the foreground. Background transfer is expected to fail cleanly because it is outside version 1.

## Security tests

### Authentication and authorization

- OTP endpoints return indistinguishable responses for known and unknown emails.
- Rate limits apply before expensive provider calls.
- A revoked device cannot obtain a session, socket ticket, or TURN credential.
- Recovery invalidates old epochs and sessions.
- Supabase identity fields controlled by the user do not grant authorization.
- Session cookies never appear in JavaScript storage, URLs, or logs.

### Browser security

- CSP blocks an injected inline script and unauthorized network origin.
- State-changing endpoints reject missing or incorrect Origin and CSRF values.
- Credentialed CORS rejects unlisted origins.
- Framing is blocked.
- Transferred metadata is rendered as text rather than HTML.

### Protocol robustness

Fuzz and property tests feed parsers malformed lengths, invalid UTF-8, duplicate JSON keys, extreme counters, unknown types, truncated ciphertext, invalid points, altered signatures, and inconsistent byte counts. Failures must terminate the transfer without exposing decrypted partial data as complete.

Nonce tests generate many frames across transfers and assert uniqueness for each derived key. Boundary tests cover counter zero, the largest accepted counter, and refusal before wraparound.

### Abuse and availability

Load tests target the cheapest public operations first: health checks, OTP start, pairing creation, socket tickets, WebSocket connects, offers, and ICE candidates. Tests verify bounded memory, bounded queues, timeouts, and useful 429 or 503 responses.

TURN tests confirm that an unauthenticated user, rejected transfer, expired transfer, or foreign device cannot obtain credentials.

Availability tests confirm that wake/readiness and probe endpoints are rate-limited as appropriate, use capped timeouts and retries, and do not become a database or diagnostic oracle.

## Manual checks

Some behaviors need a real environment:

- OTP delivery and spam placement on two email providers
- SPF and DKIM results in received headers
- WebRTC across different home, mobile, and restrictive networks
- relay selection when UDP is blocked
- foreground mobile transfer behavior
- Supabase pause and restore runbook
- Koyeb Free cold start, one-Uvicorn-worker resource limits, and WebSocket reconnect behavior
- HTTP-first wake/readiness before WSS
- the separately scheduled authenticated availability probe (three times per day by default, configurable) and its observable failure path
- Supabase pause warnings, genuine database activity from the probe, and the restore runbook
- log inspection after failed auth and transfer attempts

## Continuous integration

The initial pipeline runs formatting, linting, type checking, unit tests, migration tests, integration tests, dependency audit, secret scanning, and a production build. Browser tests may run in a separate job because they take longer.

Dependencies and lockfiles are committed. Automated update pull requests still require tests and review, particularly for Web Crypto wrappers, canonicalization, parsers, authentication clients, and database libraries.

## Release gate

A public release requires:

- all required test layers passing
- no unresolved high-severity dependency finding
- no secret detected in source, build output, or history under review
- an independent review of the threat model against the code
- successful direct and forced-relay transfers
- successful account bootstrap, pairing, revocation, and recovery
- successful Koyeb Free cold-start wake, availability state handling, and presence reconnect
- successful authenticated database-backed availability probe with no sensitive diagnostics
- clean log review
- documented browser results
- a completed email-domain test or a deliberate switch to another provider or domain

Coverage numbers can help locate untested code, but no percentage replaces the named security cases above.
