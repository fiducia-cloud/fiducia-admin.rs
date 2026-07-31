# Operator cron debugging

`GET /crons` is the operator-only troubleshooting surface for Fiducia cron jobs.
It reuses the admin app’s full authorization boundary: a verified `admin` role
from `fiducia-auth` plus an enabled operator-registry row in the isolated admin
database.

The operator supplies the canonical organization id and, optionally, a schedule
name. The server then calls the tenant-scoped `fiducia-node` cron API with the
trusted-hop secret and `x-fiducia-org-id`. Browser cookies, bearer credentials,
and arbitrary upstream URLs are never forwarded.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /crons?org=…&schedule=…&limit=…` | Server-rendered schedule inventory and newest-first run trail |
| `GET /api/admin/crons?org=…` | Operator-gated JSON schedule inventory |
| `GET /api/admin/crons/:schedule/history?org=…&limit=…` | Operator-gated JSON run history |

The debugger exposes schedule metadata, delivery status, attempts, duration,
HTTP status, error class, and trace ids. It does **not** fetch function source,
invocation payloads, environment variables, webhook URLs, or gRPC endpoints.
Webhook and gRPC targets are rendered only as redacted target kinds.

## Configuration

- `FIDUCIA_CRON_NODE_URL`: stable fiducia-node client-plane base URL used for
  cron diagnostics. When unset, the first explicit `FIDUCIA_NODE_URLS` entry is
  used. Brain-discovered addresses are intentionally not used for tenant-scoped
  requests carrying the trusted-hop secret.
- `FIDUCIA_INTERNAL_SECRET`: required trusted-hop credential. It remains
  server-side and is never rendered or logged.

Upstream redirects are disabled, calls time out after five seconds, responses
are capped at two MiB, organization and schedule inputs are bounded, and raw
upstream errors are normalized before reaching the browser or JSON API.
