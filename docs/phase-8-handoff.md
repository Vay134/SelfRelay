# Phase 8 handoff: TURN fallback and abuse resistance

This file records what the Phase 8 completion work changed, why the non-obvious choices were made, and what a reviewer should check first. It covers the commits from `41e7608` through `8598f51`. The credential-provider work that preceded them (`88ea4e1`, `8824f0b`, `c721607`) is not repeated here.

## Status

Phase 8 is complete against the exit criteria in `implementation-plan.md`. The full gate passes:

```bash
npm run quality
```

That runs prettier, eslint, `tsc -b`, and vitest for the frontend, then ruff format, ruff check, mypy strict, and pytest for the backend, then secretlint across the repository. At the time of writing: 148 backend tests, 41 frontend tests, no lint or type findings.

## Exit criteria

| Criterion | Where it is proven |
| --- | --- |
| A forced-relay transfer passes the same encryption, ordering, completion-record, and integrity checks as a direct transfer | `frontend/src/relayIntegrity.test.ts` |
| Unauthorized, foreign-device, rejected, expired, cancelled, and rate-limited callers cannot obtain TURN credentials | `backend/tests/test_turn.py` |
| Excess traffic produces bounded memory and predictable rejection | `backend/tests/test_load_bounds.py`, `backend/tests/test_socket_limits.py` |
| TURN, Supabase, and related provider failures reach a terminal user-visible state | `backend/tests/test_degradation.py`, `frontend/src/abuseResistance.test.ts` |
| No sensitive connection or cryptographic data enters metrics or logs | `backend/tests/test_metrics.py` |

## Commits

| Commit | Change |
| --- | --- |
| `41e7608` | Cleared pre-existing ruff line-length and `encode` findings that were blocking the gate |
| `17040bb` | Bounded public HTTP request bodies |
| `9f5f687` | Socket queue, signaling, and transfer capacity bounds |
| `12cf4b3` | Signaling state release on terminal transfer transitions |
| `a77f8ee` | Socket, transfer, and TURN counters |
| `f29153b` | Terminal error when the database is unreachable |
| `b680d51` | Browser retry bounds and relay-usage reporting |
| `fbad23e` | TURN outage and flooding tests |
| `8598f51` | Secretlint exemption for a negative-test fixture |

## What changed

### Request bodies

`RequestBodyLimitMiddleware` in `backend/app/security.py` rejects oversized bodies with a `413` before routing, so no handler, database call, or provider call runs first. A declared `Content-Length` is checked before anything is read. A chunked body with no declared length is buffered only up to the cap and then replayed to the application, so memory stays bounded at the limit plus one chunk. The rejection body is a fixed message that does not disclose the configured limit.

Every request model already bounded its string fields, the largest at 4096 characters, so the 64 KiB body cap is a backstop rather than the primary control.

### Socket and signaling bounds

`backend/app/presence.py` now enforces a process-wide socket cap, a per-account cap, one socket per device, per-socket outbound limits on both queued message count and queued bytes, a per-socket inbound message budget, and signaling budgets scoped per transfer, per device, and per account.

Outbound writes moved to a per-socket writer task fed by a bounded queue. Overflow closes that socket with a retryable code rather than growing the queue. `broadcast_presence` was routed through the same queue; it previously wrote directly to each socket in a loop, so one unresponsive peer could stall a whole account's broadcast.

Three parallel dictionaries tracking signaling counts, totals, and timestamps were replaced by a single `_SignalingUsage` record per transfer plus one per-account total. Releasing a transfer now returns its budget to the account in one step instead of three partial cleanups that could drift.

### Timeouts and cleanup

Reject, cancel, and expire release signaling state through `PresenceManager.release_transfer`. Stale state is pruned against `SIGNALING_STATE_RETENTION`, inactive sockets against the heartbeat timeout, and both drop their queued payloads on release. Socket disconnect already released connection state through the route's `finally` block; the queue and writer task now go with it.

Terminal transfer states were already absorbing, because `_VALID_TRANSITIONS` in the repository gives `rejected`, `cancelled`, `expired`, `completed`, and `failed` no outgoing edges. That property was untested before and is now covered directly.

### Metrics

`backend/app/metrics.py` holds a small lock-guarded counter map. Counters cover socket registration and rejection, queue overflow, send failures and timeouts, heartbeat timeouts, signaling forwards and rejections, state cleanup, transfer capacity rejection, TURN issuance, denial, rate limiting, provider failure, and direct-versus-relay usage. `PresenceManager.resource_snapshot` supplies gauges for active sockets, active signaling transfers, queue depth, and queued bytes.

Metric names are static identifiers. A test asserts that no name carries an account, device, or transfer identifier, and that none matches a list of sensitive fragments. None of the touched modules log at all.

### Graceful degradation

`backend/app/database.py` wraps pool creation and every query in a bounded timeout and raises `BackendUnavailableError`. `main.py` maps that, plus `asyncpg.PostgresError` and `asyncpg.InterfaceError`, to a single `503` with a fixed message. Startup no longer aborts when the database is unreachable; requests answer with that terminal `503` and `/health` reports `unavailable`, re-checking on each call so a transient outage can recover without a restart.

In the browser, `apiRequest` aborts on a timeout with a safe message, `PresenceSocketClient` stops after a bounded number of reconnects and reports a terminal `failed` status, `WebRtcTestSession` fails a negotiation that never connects and caps pending ICE candidates, and `TransferConsole` caps and prunes queued signals. `createTestSession` already deduplicated by transfer, so a bounded retry cannot create duplicate offers, credentials, sockets, or sessions.

## Decisions worth knowing

**Outbound delivery is now asynchronous.** `send_to_device` returns once a payload is queued, not once it is written. This is deliberate: awaiting the write let one slow peer stall another peer's socket loop for the length of the send timeout, which is the abuse shape Phase 8 exists to close. Four existing tests assumed synchronous delivery and now call `await manager.flush_outbound()`, which is also the bounded drain used at shutdown.

**Relay usage is reported over the signaling socket, not a new endpoint.** Direct-versus-relay is only observable in the browser, from `RTCPeerConnection` stats. A `connection_mode` socket message reuses the existing authentication, origin check, and per-socket message budget, and is validated against the transfer's participants before incrementing a counter. A new HTTP endpoint would have added public surface and its own rate limiting for one counter.

**Provider-error handling was deliberately narrowed.** An earlier draft mapped bare `OSError` and `TimeoutError` to `503` at the application level. Because `TimeoutError` subclasses `OSError`, that turned ordinary programming errors into service-unavailable responses. Handlers are now registered only for `BackendUnavailableError` and the two asyncpg error bases; `database.py` is responsible for translating I/O failures into the former.

**The body-limit middleware buffers rather than raising.** The first implementation raised a sentinel exception from a wrapped `receive`. FastAPI catches broad exceptions while parsing a request body and converts them to `400 There was an error parsing the body`, which swallowed the signal. Buffering to the cap is both simpler and immune to that.

## Bug found and fixed along the way

`transfer_notification` in `backend/app/transfers.py` put `datetime` objects into WebSocket payloads. Starlette's `send_json` calls `json.dumps` without a default encoder, so every real transfer notification would have raised `TypeError`, failed the send, and dropped the socket. It was invisible because the tests used a fake socket that appends payloads without serializing them.

Notifications now send `isoformat()` strings, which is what the frontend's `TransferRequest` type already expected for `created_at` and `expires_at`. Anyone reviewing the socket contract should treat this as a wire-format correction, not a new field.

## Repository state

Two gate failures predating this work were cleared so the gate could pass: ruff findings in `backend/app/adapters.py` and `backend/tests/test_adapters.py`, and a secretlint hit on the origin fixture in `backend/tests/test_config.py` that embeds userinfo credentials in a URL. That fixture is a negative test asserting the origin validator rejects embedded credentials, so it was exempted in place rather than changed.

One working-tree change was left uncommitted on purpose: a `.gitignore` entry adding `CLAUDE.md`. It is unrelated to Phase 8.

## Where to look first

- `backend/app/presence.py` carries most of the new logic and most of the risk. The outbound queue, the writer task, and `_SignalingUsage` are the parts worth reading closely.
- `backend/app/security.py` is small and self-contained; the buffering path is the part to check.
- `backend/tests/test_load_bounds.py` is the clearest single statement of what the system now refuses to do under load.

## Follow-up candidates

None of these block Phase 8.

- The limits are module constants rather than settings. If any need to differ per environment, they should move into `config.py` with validation.
- `resource_snapshot` has no exposure path. Phase 9 or the deployment work should decide whether an operator reads it through an authenticated endpoint or a log line.
- `_serve_connection`, `_record_signaling_use`, and `_release_signaling` are exercised directly by tests through their private names. If these stabilize, promoting the seams the tests need would remove that coupling.
