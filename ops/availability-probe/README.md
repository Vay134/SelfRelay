# Availability probe

This directory contains the provider-neutral operations probe for the hosted
backend. The Cloudflare Worker adapter runs the probe from a Cron Trigger;
the core check in `src/probe.ts` can be reused by another scheduler later.

Each run makes one bounded `GET` request to the backend's authenticated
`/availability/probe` route. The backend performs the database check and
returns `{"status":"ok"}` only when that check succeeds. The probe does not
retry, write application data, or claim to prevent every Supabase pause.

The default schedule is three runs per day at 00:00, 08:00, and 16:00 UTC in
`wrangler.toml`. Change the `triggers.crons` list for a different operational
cadence, keeping the schedule low frequency. The request timeout defaults to
10 seconds and is capped at 30 seconds.

## Configure and deploy

Install Wrangler in the probe package's development environment, then run the
following commands from this directory:

```text
npm install
npx wrangler secret put AVAILABILITY_PROBE_TOKEN
npx wrangler deploy --var AVAILABILITY_PROBE_URL:https://api.example.invalid/availability/probe
```

Replace the example URL with the Koyeb HTTPS endpoint. `AVAILABILITY_PROBE_URL`
is a non-secret Worker variable and may instead be configured in the Wrangler
dashboard or deployment pipeline. `AVAILABILITY_PROBE_TOKEN` must be entered
through the scheduler's secret store; never add it to `wrangler.toml`, a local
source file, a frontend `VITE_*` variable, a command committed to a script, or
an application log.

Configure the same token value as `AVAILABILITY_PROBE_TOKEN` in the Koyeb
backend secret store. The backend and Worker must use the same value, but the
value belongs only in those two host-managed secret stores. Rotate both stores
together and deploy the Worker after rotation.

For a local scheduled invocation, put development-only values in Wrangler's
ignored `.dev.vars` file or pass them through the local environment. Do not
commit that file and do not use a production token locally. A local run can be
started with:

```text
npx wrangler dev --test-scheduled
```

## Failure visibility

Every completed run emits one JSON log object containing only the component,
event, `ok`/`failed` status, an allowlisted failure reason, HTTP status, and
elapsed milliseconds. It never logs the endpoint, bearer token, response body,
or exception text. Inspect Worker invocation logs and the scheduler's alerting
for failures; the response details intentionally remain coarse.

The supported failure reasons are `configuration_missing`,
`invalid_endpoint`, `timeout`, `network_error`, `http_error`, and
`invalid_response`. A failed run is terminal for that invocation and is not
silently retried.
