# Cloud Run deployment module

This module packages the existing `backend` FastAPI application for Google
Cloud Run. The Docker build context is `backend`, so the image uses the
checked-in `backend/uv.lock` and starts the existing `app.main:app` entry point.

## Runtime contract

The checked-in service manifest encodes the Phase 11 runtime contract:

- region `asia-southeast1`
- request-based CPU allocation
- zero minimum instances and one maximum instance
- 3,600-second request timeout
- one Uvicorn worker
- HTTP/2 end-to-end disabled by the `http1` container port
- no persistent volume; the container filesystem is disposable
- a non-root application user in a pinned Python 3.12 slim image

The manifest is a placeholder template. Before applying it, replace the
uppercase placeholders with the project, image, service account, origin, and
Secret Manager resource values for the deployment. The three secret references
are names and version `1` only; put their values in Google Secret Manager and
grant the runtime service account access to those secrets.

## Build and apply

Run these commands from the repository root after creating the Artifact
Registry repository and pushing the image. Keep the image tag immutable for a
release; do not use `latest`.

```text
docker build --file ops/cloud-run/Dockerfile --tag REGION-docker.pkg.dev/PROJECT_ID/ARTIFACT_REPOSITORY/selfrelay-api:IMAGE_TAG backend
docker push REGION-docker.pkg.dev/PROJECT_ID/ARTIFACT_REPOSITORY/selfrelay-api:IMAGE_TAG
gcloud run services replace ops/cloud-run/service.yaml --project PROJECT_ID --region asia-southeast1
```

The service URL is assigned by Cloud Run. Set the `API_ORIGIN` placeholder to
that assigned origin and apply the manifest again after the first deployment.
Set `APP_ORIGIN` to the public application origin before the production
revision receives traffic.

Do not put secret values in this directory, the image, commands, or revision
plain configuration. Keep persistent application state in the configured
database; this container's local filesystem must be treated as disposable.
