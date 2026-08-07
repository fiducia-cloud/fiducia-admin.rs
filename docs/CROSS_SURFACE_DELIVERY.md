# Cross-surface delivery

Verified **2026-08-06**.

## Surfaces

- Rust admin/operator web application: `fiducia-cloud/fiducia-admin.rs`
- Flutter Android/iOS, Flutter Web/mobile web, and Flutter desktop: `fiducia-cloud/fiducia-flutter` — planned
- Rust desktop operator client: `fiducia-cloud/fiducia-desktop.rs` — planned native GPUI/no-WebView application
- Shared contracts: Fiducia interfaces, generated clients, lock/lease/consensus/cron/node/cluster/audit schemas, routes, synthetic telemetry fixtures, and conformance tests

The admin and customer planes remain separate. An operator-surface change must not be implemented by widening the customer database, customer cookie, or customer API authority.

## Judgment-based propagation

Evaluate Flutter mobile, Flutter Web, Flutter desktop, GPUI desktop, and shared contracts for every user-visible or contract-changing admin-web change. Server-only deployment, schema, observability, and security hardening may remain server-only. Native dense telemetry, keyboard workflows, local incident tools, secure storage, notifications, and background operation may be native-specific. Lock/lease/consensus/cron state, node and shard health, placement, audit semantics, operator approvals, cluster events, permissions, errors, notifications, and navigation normally propagate or require an explicit rationale and parity issue.

Operator capabilities do not need to be exposed identically on mobile. High-risk write operations may remain desktop/web-only when the risk assessment says so, but mobile/Flutter must still receive safe status, notification, approval, or handoff behavior where appropriate. Each issue and pull request records affected surfaces, omitted surfaces and rationale, accepted parity gaps, and separate validation/release status.

## Deep links

Canonical:

```text
https://<verified-fiducia-owned-host>/open/<route>?<bounded-query>
```

Fallback:

```text
fiducia://<route>?<bounded-query>
```

The exact HTTPS host must be verified. All surfaces share versioned route types and golden fixtures and support cold start, already-running delivery, authentication resume, replay/expiry rejection, browser fallback, and explicit confirmation or reauthentication before operator writes, scaling, membership changes, incident actions, lock/lease interventions, or other security-sensitive operations.

Never put internal cluster secrets, node URLs that reveal private topology, database credentials, operator session cookies, CSRF material, bearer/refresh tokens, API keys, raw audit records, private telemetry, or privileged commands in URLs. Use bounded identifiers or short-lived, single-use, audience-bound codes and validate route version, operator/org/node/shard/lock/lease/incident IDs, action, authorization, assurance level, limits, and user intent.

## Review checklist

- [ ] Flutter Android/iOS impact evaluated.
- [ ] Flutter Web/mobile-web impact evaluated.
- [ ] Flutter desktop impact evaluated.
- [ ] GPUI Rust desktop impact evaluated.
- [ ] Shared operator/cluster/client/route/fixture impact evaluated.
- [ ] Deep-link, auth-resume, and operator-approval compatibility tested where relevant.
- [ ] Admin/customer data-plane separation remains intact.
- [ ] High-risk mobile omissions have an explicit security rationale.
- [ ] Omitted surfaces have a follow-up when needed.

## Routing

- GitHub Project: [`fiducia-cloud-project` — Project 1](https://github.com/orgs/fiducia-cloud/projects/1)
- Linear project: [`github.com/fiducia-cloud`](https://linear.app/denman/project/githubcomfiducia-cloud-8fd5e1bec9d3)
- Central policy: [`cross-surface-delivery.md`](https://github.com/ORESoftware/project-registry/blob/main/docs/cross-surface-delivery.md)
- Desktop registry: [`desktop-applications.json`](https://github.com/ORESoftware/project-registry/blob/main/registry/desktop-applications.json)
