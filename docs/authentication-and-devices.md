# Authentication and device lifecycle

## Terms

An email OTP proves control of the account email. Supabase creates and verifies it. It is used for the first device and recovery.

A pairing code identifies a pending device request so a person can compare the same request on two screens. It is not sent by email and is not sufficient by itself. A trusted device must sign the approval.

An application session is an opaque FastAPI session. A device key is the ECDSA P-256 key pair held by one browser profile.

## Account bootstrap

1. The browser sends an email address to the FastAPI OTP-start endpoint.
2. FastAPI normalizes the address for lookup and applies account and network rate limits.
3. FastAPI asks Supabase Auth to send a numeric email OTP. The HTTP response does not reveal whether an account already exists.
4. The user submits the email and OTP to FastAPI.
5. FastAPI asks Supabase Auth to verify the OTP and validates the returned identity.
6. The browser generates a non-extractable ECDSA P-256 key pair.
7. The browser submits the public key, a proof-of-possession signature over a server challenge, and a device label.
8. FastAPI creates the application user if needed, registers the device in the current account epoch, and issues an application session.
9. The temporary Supabase session is revoked or discarded. Its access and refresh tokens are not stored in browser storage.

If the account already has trusted devices, this flow is treated as recovery rather than ordinary enrollment and follows the recovery policy below.

## Returning device

A valid application cookie resumes the session without another prompt. If the cookie has expired but the device key still exists, the browser requests a fresh challenge.

The signed challenge includes:

- protocol and challenge version
- challenge identifier
- account and device identifiers
- account device epoch
- server nonce
- requesting origin
- issued and expiry timestamps

FastAPI accepts the signature once, confirms that the device is active in the current epoch, and creates a new application session. Failed attempts do not reveal whether the device identifier is registered.

If IndexedDB has been cleared, the private key is gone. The browser is a new device and must pair or recover the account.

## New-device pairing

1. The new browser enters the account email and generates its device signing key.
2. FastAPI creates a pending request containing the new public-key fingerprint, random nonce, expiry, and a human-readable comparison code.
3. The new browser displays the code and waits. It does not receive an authenticated session yet.
4. An online trusted device receives a generic enrollment notification.
5. The trusted device displays the requesting device label, creation time, and comparison code. It does not display untrusted text as HTML.
6. The user compares the code on both screens and approves or rejects the request.
7. On approval, the trusted device signs a canonical statement containing the request identifier, account identifier, current epoch, new-device fingerprint, both nonces, and expiry.
8. FastAPI verifies the signature with the approving device's registered public key and atomically marks the new device active.
9. The new browser proves possession of its private key and receives an application session.

Pairing requests expire after 10 minutes. Codes are attempt limited and stored as hashes. Approval is one-time and bound to the exact new public key, so copying the visible code does not let an attacker replace that key.

## Email recovery

Email is the recovery authority in version 1. Recovery is available when no trusted device can approve the request. A successful recovery:

1. verifies a fresh email OTP
2. increments the account device epoch
3. revokes every application session
4. marks existing devices as revoked for the old epoch
5. registers the recovering browser as the first device in the new epoch
6. records a security event without storing the OTP

The UI warns that other devices will need to pair again. If a trusted device is currently online, the normal pairing flow is offered first. Email compromise can still take over the account, which is an accepted version 1 limitation.

## Application sessions

The session identifier contains at least 256 random bits and is encoded with unpadded base64url. The cookie uses a name such as `__Host-session` and these attributes:

```text
Secure; HttpOnly; SameSite=Lax; Path=/
```

It has no `Domain` attribute. The database stores a SHA-256 hash of the random token, never the token itself. A session record includes its user, device, account epoch, creation time, last-use time, idle expiry, absolute expiry, and revocation time.

FastAPI rotates the session after email verification, device enrollment, and recovery. It revokes the previous value in the same transaction where practical. A normal session expires after 30 idle days or 90 total days.

## CSRF and CORS

The frontend and API use different origins. Browser requests include credentials, and FastAPI allows only explicit frontend origins. Wildcard origins are forbidden with credentialed requests.

Unsafe requests require an exact allowed `Origin` header and a session-bound CSRF token in a custom header. The CSRF value is not the session identifier. Login and recovery endpoints use strict rate limits and Origin checks even before a session exists.

WebSockets use a short-lived, single-use ticket obtained through a CSRF-protected HTTP request. Query strings and logs must not contain the application session token.

## Device-key storage

The browser generates the ECDSA private key with `extractable` set to `false`. It stores the resulting `CryptoKey` in IndexedDB. The public key is exported as DER SPKI and the fingerprint is:

```text
base64url(SHA-256(spki_der))
```

The UI displays a shortened fingerprint for comparison but protocol messages use the full value. Clearing site data destroys the local credential. Private keys are not synchronized or backed up by the application.

## Revocation

A user can revoke another device or session from any active trusted device. Revoking a device also revokes its sessions, closes its sockets, cancels its pending offers, and prevents new challenge authentication.

Deleting an account first revokes sessions and devices, then removes application records and requests deletion of the Supabase Auth identity. The deletion flow must not assume that deleting an Auth user instantly invalidates every already-issued token.

## Email-service boundary

FastAPI exposes an `AuthGateway` interface for OTP start and verification. The production adapter calls Supabase Auth. Unit and integration tests use a fake adapter that never sends email.

The fake is available only under an explicit test environment. Production startup fails if it is selected. Tests may inspect an OTP through the fake object, but no HTTP response or application log returns an OTP.

Supabase talks to the chosen SMTP provider. Resend credentials, if used, live in Supabase's protected configuration rather than FastAPI or frontend source code.

## Abuse controls

Limits are configured separately for email address, account, IP address, session, and device where those identifiers exist. Initial values should be conservative and adjusted from observed false positives.

At minimum, controls cover OTP requests and attempts, pairing creation and guesses, device challenges, session creation, WebSocket tickets, device revocation, and recovery. Repeated failures create a security event and may trigger a temporary cooldown. Responses stay generic so the control does not become an account-enumeration oracle.

