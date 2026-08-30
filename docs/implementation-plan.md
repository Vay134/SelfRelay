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

- write the initial Supabase migration for users, devices, sessions, challenges, device-linking OTPs, transfers, socket tickets, security events, and rate limits
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

## Phase 3: device identity and login

Add the browser credential that replaces repeated email login.

Work:

- generate and persist a non-extractable ECDSA P-256 key in IndexedDB
- export SPKI public keys and calculate fingerprints
- implement device proof of possession during first registration
- implement one-time server challenges for returning-device login
- add device listing, naming, and revocation
- implement email fallback that leaves other devices unchanged
- provide clear UI when site data has removed the device key

Exit criteria:

- reloading preserves the device credential
- an expired application session can be renewed with a valid device signature
- altered, expired, replayed, and revoked-device challenges fail
- email fallback leaves other devices and sessions unchanged in one tested workflow

## Phase 4: device linking

Register a new browser without sending another email when a trusted device is available.

Work:

- let an active device create a short-lived device-linking OTP
- let a new device generate its own key, enter the OTP, and choose an editable default label
- consume the OTP and atomically register the new device after proof of possession
- limit attempts, enforce expiry, and consume the OTP once
- add security events for creation and redemption

Exit criteria:

- an active device can link one new public key with one OTP
- a copied or replayed OTP cannot enroll a second device
- cross-account, expired, replayed, and double-consumption cases fail
- an invalid OTP never receives a session

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
- issue credentials only for an authenticated active-device transfer
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

- build account, device, device-linking, send, receive, progress, and error screens
- add explicit confirmation before enrollment, email fallback, device logout, and download
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

## Phase 10: hosting availability module

Add a small availability boundary around the hosted deployment without changing the transfer, presence, or protocol modules already built in Phases 0 through 6.

Work:

- create a frontend availability wrapper/module that sends an HTTP wake/readiness request before handing control to the existing presence/WebSocket client
- place the frontend wrapper/module under `frontend/src/availability/`, the backend package/router under `backend/app/availability/`, and the provider-neutral operations probe under `ops/availability-probe/`
- expose bounded availability states such as `starting`, `ready`, `degraded`, and `failed`, with capped retries, backoff, and jitter
- create a backend availability package/router with minimal public wake, readiness, and probe surfaces
- keep the backend database connectivity probe bounded by a short timeout and return only a safe status, never database details or service diagnostics
- create a provider-neutral operations availability probe/deployment package, initially scheduled with Cloudflare Worker Cron three times per day by default and configurable for operations needs, that authenticates and exercises the end-to-end path so Supabase Free receives genuine database activity
- keep probe credentials in the backend host and scheduler secret stores; never place them in source, frontend configuration, logs, or user-visible errors
- compose and wire these modules only at the application boundaries with the existing Phase 0 through 6 modules later; the availability layer wakes the backend and delegates reconnection to the presence client rather than duplicating its reconnect loop, and no hosting-provider branches enter existing presence, transfer, or protocol modules
- add unit and integration tests for state transitions, retry caps, jitter bounds, probe authentication, database timeouts, safe diagnostics, and terminal failure behavior

Exit criteria:

- a cold backend can be woken by HTTP before the client attempts WSS, then handed off to the existing presence/WebSocket client
- availability states reach a bounded terminal failure instead of remaining pending forever, and retry behavior is capped and observable without sensitive details
- the backend availability package exposes only the intended safe status/probe behavior and cannot be used as a database or diagnostic oracle
- the scheduled authenticated probe completes a genuine database-backed end-to-end check and reports failures without claiming to prevent every Supabase pause
- the new modules pass unit and integration tests without changing the Phase 0 through 6 module contracts or duplicating presence reconnect logic

## Phase 11: hosted deployment and email

Deploy the same tested artifacts and complete the manual service checks.

Status: in progress.

Work:

- deploy the frontend to its Cloudflare Pages `pages.dev` hostname
- create a dedicated `ops/cloud-run/` deployment module for the container, service settings, and deployment instructions instead of adding Google-specific branches to application modules
- create a narrowly scoped Pages Function gateway under the frontend deployment boundary that proxies only the required HTTP and WebSocket routes to Cloud Run; keep browser traffic on the Pages origin so the host-only `SameSite=Lax` session cookie remains first-party
- set the production `VITE_API_ORIGIN` to the Pages origin and reduce the production CSP `connect-src` to `'self'` after the gateway is in place
- deploy one Uvicorn worker in the pinned image to Google Cloud Run region `asia-southeast1` with request-based billing, zero minimum instances, one maximum instance, and a 60-minute request timeout; keep HTTP/2 end-to-end disabled for WebSocket support and configure a billing budget and alerts ([Cloud Run overview](https://cloud.google.com/run/docs/overview/what-is-cloud-run), [WebSocket guidance](https://cloud.google.com/run/docs/triggering/websockets))
- keep durable sessions, devices, offers, device-linking records, and other authoritative state in Supabase; treat the Cloud Run filesystem as disposable
- create the hosted Supabase project and apply migrations
- verify an individual sender address in Brevo and create a dedicated SMTP key
- configure Supabase custom SMTP with Brevo's SMTP relay, port `587`, SMTP login, SMTP key, verified sender address, and sender name `SelfRelay`
- test the displayed Brevo sender identity and OTP delivery to external Gmail and Outlook recipients; accept and document any provider-managed sender replacement caused by not owning a domain
- configure production secrets, origins, cookies, health checks, and monitoring
- store Cloud Run secrets in Google Secret Manager under a dedicated service account; keep Brevo credentials only in Supabase and gateway secrets only in Cloudflare
- deploy the separate availability probe from Phase 10 with the intended provider-neutral package under `ops/availability-probe/` and a configurable Cloudflare Worker Cron schedule that defaults to three runs per day; verify its authenticated database-backed check and failure visibility
- verify that the frontend performs an HTTP wake/readiness request through the Pages gateway before WSS, and that the existing presence client reconnects cleanly after a Cloud Run cold start, request timeout, deployment, or restart
- run direct and relay transfers across separate networks
- write the Cloud Run cold-start and billing-alert, Supabase pause-warning and restore, key-rotation, and incident runbooks

Exit criteria:

- external test accounts receive and verify OTPs
- production bundles and logs contain no secrets
- HTTPS, same-origin gateway, cookies, CORS, CSRF, WebSocket, database grants, and TURN checks pass
- the browser uses the Pages origin for API and WebSocket traffic; direct browser use of the Cloud Run URL is neither required nor supported
- the Cloud Run deployment uses `asia-southeast1`, request-based billing, zero minimum instances, one maximum instance, one Uvicorn worker, a disposable filesystem, and a 60-minute request timeout; cold-start wake and WebSocket reconnect behavior are verified
- Google, Supabase, Brevo, Cloudflare, and TURN secrets exist only in their intended host-managed secret stores
- the scheduled probe supplies regular genuine Supabase database activity, while pause warnings remain monitored and the restore procedure is tested
- an external user can complete a transfer without local infrastructure

An owned domain is optional for version 1. Adding one later should improve sender recognition and email authentication without changing the application protocol. Raising Cloud Run above one instance remains blocked on shared presence and signaling fanout. Earlier phases do not change.

## Phase 12: release validation and operational documentation

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
