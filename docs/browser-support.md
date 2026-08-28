# Browser support and manual verification

This application needs a secure context (HTTPS in a hosted environment; `localhost` is suitable for local development), IndexedDB, Web Crypto, WebRTC, and WebRTC DataChannels. The matrix below describes the intended v1 targets, not completed browser certification.

## Desktop targets

| Browser | Support position | Current repository evidence |
| --- | --- | --- |
| Chrome / Chromium | Supported target when using a current desktop release | No manual end-to-end browser run recorded yet |
| Microsoft Edge | Supported target when using a current desktop release | No manual end-to-end browser run recorded yet |
| Firefox | Best effort; verify DataChannel and storage behavior on the current release | No manual end-to-end browser run recorded yet |
| Safari on macOS | Best effort; verify storage persistence, permissions, and WebRTC negotiation on the current release | No manual end-to-end browser run recorded yet |

Mobile browsers, background transfers, and old browser releases are outside the v1 support claim. A browser result should be recorded only after the checklist below completes; automated unit tests and a successful production build do not count as a browser transfer result.

## Manual core-transfer checklist

Record the browser name, version, operating system, date, network conditions, and direct/relay result for each run.

1. Open two separate desktop browser profiles or private contexts for the same account. Confirm both pages are served from a secure context.
2. Register or pair the second browser. Compare the complete six-digit code and device fingerprint before approving it.
3. Reload both pages and confirm the trusted-device session and device key persist.
4. On the sender, open **Transfer devices**, choose the online recipient, and send a transfer request.
5. On the recipient, accept the request. Confirm that file name and size are not shown before acceptance and channel setup.
6. Send an empty file, a small file, and a file whose size is not an even multiple of the transfer chunk size. Confirm progress reaches **Verified** and the downloaded bytes match the originals.
7. Confirm the download requires an explicit confirmation and is offered only after verification.
8. Cancel once from each side, and repeat with a deliberately interrupted or unavailable peer. Confirm the UI reaches a clear terminal state and can start another transfer.
9. With only the keyboard, move through the workspace tabs with Tab and Arrow/Home/End keys, activate each tab with Enter or Space, open a confirmation, cycle focus with Tab/Shift+Tab, close with Escape, and confirm focus returns to the triggering control.
10. Repeat one transfer in a restrictive network that forces relay if available. Record whether it completes and whether the UI reports the connection mode.

## Result log

Until real browser runs are recorded, do not describe any target above as passed. Add a dated entry here with the exact browser version and checklist outcome. The repository's frontend unit suite provides regression coverage for protocol, transfer, security-boundary, and tab-semantics code, but it does not replace this manual two-browser workflow.

### 2026-08-28 — Local Chromium/in-app browser smoke run

- Environment: local fake backend and localhost frontend; one isolated browser profile (exact browser build not recorded).
- Passed: account enrollment; confirmation dialogs, including Escape handling and focus return; trusted session and device-key persistence after reload; keyboard workspace navigation; signed-in transfer workspace readiness; and no browser-console errors.
- Not run: a send/receive transfer, download confirmation after receipt, direct mode, relay mode, or Chrome/Edge/Firefox/Safari multi-profile verification. Only one isolated browser profile was available, so the two-profile transfer workflow and cross-browser verification could not be completed.
- This result confirms local workspace readiness only; it is not an end-to-end transfer certification.
