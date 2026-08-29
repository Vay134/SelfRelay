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

Application code talks to Supabase Auth rather than directly to an email vendor. Supabase sends OTP email through Brevo custom SMTP. Tests replace the Supabase boundary with a fake; production refuses to start with that fake enabled.

Brevo was selected because it can verify an individual sender and deliver to external recipients without an owned domain. Brevo may replace a free sender address with a provider-managed transactional address, so the Phase 11 release check records sender presentation and delivery to unrelated providers. A later custom domain or SMTP provider change must not require changes to the application protocol.

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

Cloudflare Pages hosts the static frontend and a narrowly scoped same-origin gateway. Google Cloud Run hosts FastAPI in `asia-southeast1` with request-based billing, zero minimum instances, one maximum instance, one Uvicorn worker, and a 60-minute request timeout. The container filesystem is disposable. The one-instance limit preserves the current in-memory presence design and bounds cost, but it also limits availability and throughput. [Cloud Run overview](https://cloud.google.com/run/docs/overview/what-is-cloud-run), [Cloud Run WebSockets](https://cloud.google.com/run/docs/triggering/websockets)

Supabase Free hosts Auth and PostgreSQL. Cloudflare provides managed TURN. Separate availability modules under `frontend/src/availability/`, `backend/app/availability/`, and `ops/availability-probe/` wake the backend over HTTP before handing control to the existing presence/WebSocket client and run a configurable authenticated probe three times per day by default to supply regular genuine database activity through a scheduled deployment. The probe does not guarantee that Supabase will never pause, so pause warnings and restoration remain operational responsibilities. These modules are composed and wired at application boundaries; no hosting-provider branches enter existing presence, transfer, or protocol modules. This configuration meets the small-scale deployment requirement but provides no high-availability guarantee and is unsuitable for a critical service.

## D011: provider-assigned public URLs

Status: accepted

Version 1 uses the Cloudflare Pages `pages.dev` hostname as the public browser origin and Cloud Run's assigned `run.app` URL as the backend upstream. It does not require a purchased or community-managed domain.

Because a direct `pages.dev` to `run.app` browser call would make the host-only session cookie cross-site, a narrowly scoped Pages Function proxies HTTP and WebSocket control traffic to Cloud Run. The browser uses one Pages origin; FastAPI still performs authentication, authorization, exact Origin checks, CSRF protection, and rate limiting. A future custom domain must preserve this same-origin property or deliberately redesign the cookie boundary.

## D012: version 1 recovery policy

Status: accepted

Email is the final recovery authority because MFA and recovery codes are outside version 1. Successful recovery increments the account device epoch and revokes application sessions. Previously registered devices must pair again.
