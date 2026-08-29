# Phase 11 operations

Deploy Cloud Run from `ops/cloud-run` with request-based billing, zero minimum
instances, one maximum instance, a 3,600 second timeout, and one Uvicorn worker.
Use the `selfrelay-cloud-run` service account and Secret Manager references only.

Set the Pages production secret `UPSTREAM_ORIGIN` to the assigned Cloud Run
HTTPS origin. Keep `VITE_API_ORIGIN=https://selfrelay.pages.dev`. Deploy Pages
only after the gateway secret is present. The availability probe uses the same
`selfrelay-availability-probe-token` value as Cloud Run, stored as a Cloudflare
secret.

TURN is disabled. Do not provision Cloudflare Realtime TURN until a separate
cost review approves it. Brevo SMTP remains configured only in Supabase.

For a failed Cloud Run revision, inspect revision logs, verify its secret
bindings and exact Pages origin, then roll back to the prior revision. Budget
alerts provide visibility only and are not a spending cap. If Supabase pauses,
restore the project in its dashboard, check the authenticated availability
probe, and retry the readiness endpoint through Pages.

Rotate a compromised credential in its owning provider, add a new Secret
Manager version or Pages secret, deploy a new revision, then revoke the old
value. Never put a secret in Git, frontend configuration, or logs.
