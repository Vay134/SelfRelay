# Implementation plan

## Working rules

Each phase ends with runnable tests and a short review against the relevant documentation. Later phases may change an internal implementation, but they must not weaken a documented invariant without an explicit design update.

Production secrets are not needed until the deployment phase. External services sit behind interfaces so local and continuous-integration tests remain deterministic.

## Phase 0: repository foundation

Build the project skeleton and make the quality checks repeatable.

Work:

- create `frontend`, `backend`, `shared/protocol-fixtures`, and `supabase/migrations`
- configure React, TypeScript, Vite, FastAPI, and the Python package layout
- pin dependencies and commit lockfiles
- add formatting, linting, type checking, unit-test, and secret-scanning commands
- add example environment files containing names and safe placeholders only
- add a CI workflow that runs without hosted service credentials
- add structured logging with redaction tests

Exit criteria:

- frontend and backend health pages run locally
- one command runs the local quality suite
- a production build succeeds
- secret scanning passes

## Phase 1: database and backend boundaries

Create the private schema and the application service boundaries before adding public auth flows.

Work:

- write the initial Supabase migration for users, devices, sessions, challenges, pairing, transfers, socket tickets, security events, and rate limits
- create a limited FastAPI database role and explicit grants
- implement repositories with parameterized queries and transaction boundaries
- define `AuthGateway` and `TurnCredentialProvider` interfaces with test fakes
- add configuration validation and refuse test adapters in production
- implement expiry cleanup in bounded batches

Exit criteria:

- migrations pass on a clean database
- privilege tests prove that public Supabase roles cannot read application tables
- repository integration tests cover ownership and concurrent consumption

## Phase 2: email bootstrap and application sessions

Implement identity bootstrap without depending on a live SMTP provider.

Work:

- add generic OTP-start and OTP-verify endpoints through `AuthGateway`
- add email normalization and rate limits
- implement opaque session creation, hashing, expiry, rotation, and revocation
- set the secure host-only cookie
- implement CSRF token issuance and exact Origin checks
- add current-session, logout, and session-list endpoints
- ensure Supabase tokens never enter browser storage

Exit criteria:

- the fake Auth adapter completes bootstrap in integration tests
- known and unknown email responses are indistinguishable at the API contract level
- CSRF, CORS, expiry, and revocation negative tests pass
- production cannot start with the fake Auth adapter

## Phase 3: device identity, login, and recovery

Add the browser credential that replaces repeated email login.

Work:

- generate and persist a non-extractable ECDSA P-256 key in IndexedDB
- export SPKI public keys and calculate fingerprints
- implement device proof of possession during first registration
- implement one-time server challenges for returning-device login
- add device listing, naming, and revocation
- implement account epoch rotation and session invalidation for email recovery
- provide clear UI when site data has removed the device key

Exit criteria:

- reloading preserves the device credential
- an expired application session can be renewed with a valid device signature
- altered, expired, replayed, and revoked-device challenges fail
- recovery invalidates old devices and sessions in one tested workflow

## Phase 4: trusted-device pairing

Register a new browser without sending another email when a trusted device is available.

Work:

- create pending pairing requests with a comparison code and public-key fingerprint
- notify online trusted devices
- build approval and rejection screens on both sides
- sign a canonical approval statement on the trusted device
- verify the signature and atomically register the new device
- limit attempts, enforce expiry, and consume approval once
- add nuisance-request suppression and security events

Exit criteria:

- a trusted device can approve the exact requested public key
- a copied code cannot enroll a substituted key
- cross-account, expired, replayed, and double-consumption cases fail
- a rejected request never receives a session

## Phase 5: presence and signaling

Build the control plane needed by WebRTC before sending file data.

Work:

- issue single-use WebSocket tickets from authenticated HTTP
- validate socket Origin and bind each connection to one device
- implement heartbeat-based presence
- list online devices on the same account
- add generic offer, accept, reject, cancel, and expiry transitions
- forward bounded SDP and ICE messages only between the selected devices
- enforce queue and message-size limits

Exit criteria:

- two browser contexts can see each other and negotiate a test DataChannel
- a foreign account cannot observe presence or route signaling
- reused tickets, oversized messages, invalid transitions, and stale offers fail
- a backend restart produces a clear reconnect or cancellation state

## Phase 6: cryptographic protocol library

Implement the protocol as a testable TypeScript module before attaching real files.

Work:

- implement strict RFC 8785 canonicalization or adopt a small pinned implementation
- implement SPKI and P1363 conversion helpers
- build signed offer and answer validation
- derive transcript-bound direction keys and nonce prefixes
- implement binary frame encoding, AES-256-GCM, counters, and confirmation
- create shared fixtures for valid and invalid messages
- add fuzz and property tests for parsing, state, and nonce uniqueness

Exit criteria:

- fixed fixtures produce the documented fingerprints, signatures, transcript, keys, and ciphertext
- both peers reject tampering, replay, wrong identity, wrong epoch, and unknown versions
- no transfer reuses ephemeral key material or an AES-GCM nonce

## Phase 7: encrypted file transfer

Connect the protocol to the browser file and WebRTC APIs.

Work:

- send the encrypted manifest only after handshake confirmation
- read and encrypt bounded chunks without loading the full input first
- implement DataChannel backpressure
- calculate incremental SHA-256 on both peers
- send and verify the signed completion record
- expose the download only after all checks pass
- implement cancellation, progress, cleanup, and safe file-name handling
- enforce the 250 MB limit and one inbound transfer per device

Exit criteria:

- empty, small, irregular, and 250 MB test files arrive byte for byte
- memory stays bounded on the sender during the maximum-size test
- a modified, missing, duplicated, or reordered frame prevents completion
- rejecting an offer reveals no file metadata

## Phase 8: TURN fallback and abuse resistance

Exercise the path used on restrictive networks and tighten the public endpoints.

Work:

- implement the Cloudflare TURN provider behind the existing interface
- issue credentials only after an accepted transfer
- add short TTLs and issuance limits
- support a relay-only test mode outside production UI
- tune request, socket, candidate, offer, and concurrency limits
- add bounded queues, timeouts, and cleanup metrics
- test graceful degradation when TURN or Supabase is unavailable

Exit criteria:

- a forced-relay transfer passes the same integrity checks as a direct transfer
- unauthorized and expired transfers cannot obtain TURN credentials
- load tests show bounded memory and predictable rejection
- provider failures reach a terminal user-visible state

## Phase 9: interface and browser hardening

Finish the user flows and browser security controls.

Work:

- build account, device, pairing, send, receive, progress, and error screens
- add explicit confirmation before enrollment, recovery, revocation, and download
- add CSP and the remaining browser headers
- remove inline scripts and unnecessary remote resources
- test hostile labels, file names, MIME types, and error text
- add accessibility checks and keyboard operation
- document supported and best-effort browser results

Exit criteria:

- the full workflow is understandable without developer tools
- CSP and framing tests pass
- untrusted text cannot become markup or script
- supported desktop browsers pass the core transfer suite

## Phase 10: hosted deployment and email

Deploy the same tested artifacts and complete the manual service checks.

Work:

- deploy the frontend to Cloudflare Pages
- deploy the pinned backend image to Koyeb Eco Micro in Singapore
- create the hosted Supabase project and apply migrations
- request the `is-a.dev` records for frontend and API
- test the Resend sending subdomain and submit its DNS records
- configure Supabase custom SMTP only after domain verification
- configure production secrets, origins, cookies, health checks, and monitoring
- run direct and relay transfers across separate networks
- write the pause, restore, key-rotation, and incident runbooks

Exit criteria:

- external test accounts receive and verify OTPs
- production bundles and logs contain no secrets
- HTTPS, cookies, CORS, CSRF, WebSocket, database grants, and TURN checks pass
- an external user can complete a transfer without local infrastructure

If `is-a.dev` or Resend verification fails, this phase switches to a purchased domain or another compatible SMTP provider. Earlier phases do not change.

## Phase 11: release validation and operational documentation

Compare the implementation with the claims made in this documentation.

Work:

- run the complete release gate in `testing-strategy.md`
- perform a focused manual review of authentication, authorization, crypto, logging, and deployment
- resolve dependency and secret-scan findings
- update diagrams and protocol details that changed during implementation
- record release evidence for critical user workflows
- add measured performance results for direct and relayed transfers
- document known limitations and observed operational constraints

Exit criteria:

- documentation and code describe the same behavior
- no unresolved high-severity security finding remains
- known limitations are visible in the README
- the repository includes reproducible setup and test commands

## Deferred work

Later versions may add resumable transfers, several files per session, cross-account sharing, MFA or passkeys, native clients, background operation, encrypted offline storage, multiple backend instances, and stronger protection against malicious web delivery. Each item requires a new design and threat-model review.
