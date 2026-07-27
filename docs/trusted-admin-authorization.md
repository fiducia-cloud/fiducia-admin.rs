# Trusted admin authorization boundary

Linear: DEN-253

Every real admin request still presents a Supabase access token through the canonical host-only admin cookie or an explicit bearer header. `fiducia-admin` sends that credential directly to the configured `fiducia-auth` `/v1/me` endpoint. A successful signature/session check is now necessary but no longer sufficient.

The admin application requires all of the following from the versioned authorization context produced by `fiducia-auth`:

- `version = 1`;
- the `fiducia-admin` surface audience;
- normalized `admin` or `operator` role;
- `admin:read` and `admin:operate` capabilities;
- `admin:write` additionally for the `admin` role;
- no unknown or duplicate version-1 audiences, roles, or capabilities.

Raw `/v1/me.user.roles` strings are deserialized only for backward wire compatibility and are never consulted for authorization. A browser-supplied role header, customer cookie, customer-only audience, unknown future vocabulary, malformed response, or old auth response without the versioned context fails closed before a `Session` is created.

## Rollout dependency

Deploy the additive `fiducia-auth` producer PR before this consumer. During a mixed-version rollout, an old auth replica does not return `authorization`; this admin build rejects that response instead of silently falling back to raw roles. Use normal rolling-deployment readiness and drain behavior to keep traffic on compatible auth replicas.

## Deliberate follow-up

This PR establishes the receiving-surface gate and normalized role/capability contract. DEN-253 remains open for a route-by-route capability matrix that distinguishes read, operate, and write handlers; the customer consumer; explicit dual-surface administration workflow; migration inventory; and end-to-end negative tests across auth, customer, admin, edge, and proxies.
