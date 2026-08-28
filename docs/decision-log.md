# Decision log

This file records choices that affect several parts of the system. It is not a changelog. Each entry describes the design that implementation should follow.

## D001: browser application

Status: accepted

The client is a React and TypeScript web application built with Vite. A browser client works across desktop and mobile platforms without separate native releases. The tradeoff is that the web host supplies the cryptographic code and must be trusted.

## D002: traditional Python backend

Status: accepted

FastAPI owns the public API, application sessions, device registry, presence, signaling, authorization, audit events, and TURN credential issuance. This centralizes security-sensitive policy enforcement and keeps the browser, backend, and database trust boundaries explicit.

## D003: Supabase as managed infrastructure

Status: accepted

Supabase provides hosted PostgreSQL and email OTP identity proof. The browser does not query application tables through the Supabase Data API. FastAPI uses a limited database role and remains responsible for account-level authorization.

Supabase is not the application session store exposed to the browser. This avoids relying on paid session-lifetime controls and keeps session revocation under application control.

## D004: provider-neutral authentication email

Status: accepted

Application code talks to Supabase Auth rather than Resend. Supabase sends OTP email through a configured SMTP provider. Tests replace the Supabase boundary with a fake; production refuses to start with that fake enabled.

Resend is the first SMTP provider to test. Its acceptance of an `is-a.dev` sending domain is unresolved. A different SMTP service or a purchased domain must not require changes to the application protocol.

## D005: trusted-device login

Status: accepted

Email OTP is reserved for the first device and account recovery. A registered device can start a new session by signing a server challenge. A new device normally obtains approval from an online trusted device through a short-lived pairing request.

## D006: WebRTC data path

Status: accepted

Files travel over an ordered WebRTC DataChannel. The peers try direct connectivity first. Cloudflare TURN relays traffic when direct connectivity fails. FastAPI carries signaling messages but never file chunks.

## D007: application-layer encryption

Status: accepted

WebRTC already encrypts its transport. The application adds its own authenticated encryption so a TURN service or passive infrastructure compromise cannot expose file content.

The suite is ECDSA P-256 for device signatures, ephemeral ECDH P-256 for transfer agreement, HKDF-SHA-256 for derivation, and AES-256-GCM for frames. P-256 was chosen for Web Crypto interoperability across the target browsers.

## D008: trusted web host

Status: accepted

The web host and backend are trusted to serve honest code and maintain the device public-key directory. The project can describe files as encrypted end to end under this model, but it must state that a compromised host can serve altered JavaScript.

## D009: no server file storage

Status: accepted

Version 1 has no offline inbox and does not use Supabase Storage. This reduces stored sensitive data and avoids turning backend bandwidth into the normal transfer bottleneck. It also means both devices must remain online.

## D010: low-cost managed hosting

Status: accepted

Cloudflare Pages hosts the static frontend. Koyeb runs one Free FastAPI instance in Frankfurt, with one Uvicorn worker, 512 MB RAM, 0.1 vCPU, and 2 GB of ephemeral disk. The instance automatically scales to zero after one idle hour, a Free behavior that cannot be disabled; custom scaling and persistent volumes are not used, and the deployment has no production SLA. [Koyeb instance reference](https://www.koyeb.com/docs/reference/instances), [scale-to-zero documentation](https://www.koyeb.com/docs/run-and-scale/scale-to-zero)

Supabase Free hosts Auth and PostgreSQL. Cloudflare provides managed TURN. Separate availability modules under `frontend/src/availability/`, `backend/app/availability/`, and `ops/availability-probe/` wake the backend over HTTP before handing control to the existing presence/WebSocket client and run a configurable authenticated probe three times per day by default to supply regular genuine database activity through a scheduled deployment. The probe does not guarantee that Supabase will never pause, so pause warnings and restoration remain operational responsibilities. These modules are composed and wired at application boundaries; no Koyeb-specific branches enter existing presence, transfer, or protocol modules. This configuration meets the small-scale deployment requirement but provides no high-availability guarantee and is unsuitable for a critical service. Paid Koyeb Eco Micro in Singapore is the upgrade path if the Free instance becomes unsuitable, not the current choice.

## D011: free project hostname

Status: accepted with a pending test

The first public hostname will use `is-a.dev` if the registration is approved. The planned layout is a project root for the frontend, an `api` subdomain for FastAPI, and an `auth` subdomain for email sending.

The account does not own the parent zone. DNS changes depend on community review, and Resend states that sending domains must not be shared or public. Domain verification therefore remains a release gate. A purchased domain is the fallback.

## D012: version 1 recovery policy

Status: accepted

Email is the final recovery authority because MFA and recovery codes are outside version 1. Successful recovery increments the account device epoch and revokes application sessions. Previously registered devices must pair again.
