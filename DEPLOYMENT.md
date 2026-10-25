# Deployment

`docker compose up --build -d` starts PostgreSQL, a one-shot Alembic migration, the FastAPI service, a durable scan worker and nginx/React. First run `make setup` to generate the database secret. Create an administrator using `make bootstrap EMAIL=you@example.com`, then `make demo`. Application and API bind to loopback.

Inspect status with `docker compose ps` and logs with `docker compose logs --tail=100 backend worker`. Do not publish logs containing real resource metadata. Preserve the named PostgreSQL volume and back up before upgrades. `docker compose down` does not delete data.

For production, terminate HTTPS at a trusted reverse proxy; restrict origins and network ingress, provide managed secret injection, replace per-process rate limits, provision backup/restore, configure an OpenTelemetry exporter/collector, and independently review authorization and data retention. OpenTelemetry instrumentation hooks are included; a remote telemetry destination is not enabled by default.

No Kubernetes, multi-tenant deployment, high-availability worker lease renewal, or automatic cloud remediation is provided. See PROGRESS.md for actual Docker validation and outstanding items.
