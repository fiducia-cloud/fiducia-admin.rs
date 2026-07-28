# Operator cron debugging

`fiducia-admin` exposes an operator-only cron debugger at `/crons` and a
metadata-only JSON projection at `/api/admin/crons`.

The debugger does not connect to customer storage and does not trust browser
credentials for service-to-service calls. After the existing admin gate verifies
an operator, the BFF builds a new request containing only:

- the configured trusted-hop credential;
- the canonical `x-fiducia-org-id` selected by the operator;
- valid W3C `traceparent` and `tracestate` headers.

Trace forwarding accepts only a version `00` `traceparent` with its exact wire
length, lowercase hexadecimal fields, and non-zero trace and parent IDs.
`tracestate` is forwarded only with a valid `traceparent`, must be non-empty
printable ASCII, and is capped at 512 bytes. Invalid browser trace context is
dropped rather than propagated across the trusted-hop boundary.

`Cookie` and browser `Authorization` are never forwarded. Redirects are disabled,
requests time out after five seconds, and response bodies are streamed under a
two-MiB cap.

## Search

An organization is required. Operators can narrow results by schedule, run/fire
id, trace id, function UUID, a bounded epoch-millisecond window, and result
limit. Run-id, trace-id, and time-window searches require a schedule so the
admin BFF never performs an unbounded cross-tenant scan.

The page shows schedule state, target summary, bounded run history, attempts,
duration, HTTP status, normalized error class, trace/span identifiers, and
redacted function metadata. When Grafana is configured, trace identifiers link
to Tempo and to a matching Loki query.

Function source, environment values, entry commands, container settings,
invocation requests, and payloads are recursively removed from the admin
response. Schedule projections rebuild each target from its safe kind; only a
function UUID may remain for function targets. Webhook and gRPC destinations,
headers, bodies, requests, and payloads are removed before HTML or JSON
serialization.

## Mutations

The UI supports pause, resume, and manual trigger. It deliberately does not offer
source viewing, source editing, schedule deletion, or function deletion.

Every mutation follows this order:

1. re-verify the operator and browser CSRF contract;
2. append an `*.requested` event to the isolated admin audit log;
3. call the tenant-scoped scheduler;
4. append an `*.completed` or `*.failed` outcome event.

Browser calls to the JSON mutation API are rejected; browser operators must use
the CSRF-protected form routes. Bearer-authenticated operator API clients may use
the JSON routes.

## Configuration

- `FIDUCIA_CRON_NODE_URL`, falling back to the first `FIDUCIA_NODE_URLS` entry;
- `FIDUCIA_INTERNAL_SECRET`;
- `FIDUCIA_LAMBDA_SERVICE_URL`;
- `FIDUCIA_LAMBDA_SERVER_AUTH_SECRET`;
- `FIDUCIA_GRAFANA_PUBLIC_URL` for optional Tempo/Loki links.

A missing URL or secret disables that dependency and requests fail closed with a
short, URL-free error class. Secrets, customer source, payloads, and raw upstream
errors are never written to spans or HTML/JSON responses.
