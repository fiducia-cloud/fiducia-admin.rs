# Trusted admin authorization boundary

Linear: DEN-253

Every real admin request still presents a Supabase access token through the canonical host-only admin cookie or an explicit bearer header. `fiducia-admin` sends that credential directly to the configured `fiducia-auth` `/v1/me` endpoint. A successful signature/session check is necessary but no longer sufficient.

The admin application requires all of the following from the versioned authorization context produced by `fiducia-auth`:

- `version = 1`;
- the `fiducia-admin` surface audience;
- normalized `admin` or `operator` role;
- `admin:read` and `admin:operate` capabilities;
- `admin:write` additionally for the `admin` role;
- no unknown or duplicate version-1 audiences, roles, or capabilities;
- audiences and capabilities that exactly match the normalized role combination.

Raw `/v1/me.user.roles` strings are deserialized only for backward wire compatibility and are never consulted for authorization. A browser-supplied role header, malformed response, unknown future vocabulary, inconsistent role/audience/capability combination, or old auth response without the versioned context fails closed before a `Session` is created.

A structurally valid customer-only context remains an authenticated identity with `is_admin = false`. Admin route gates therefore reject it as a verified non-operator with `403`, rather than misclassifying it as an absent or invalid credential with `401`. This distinction does not grant any admin capability. The canonical customer cookie is still isolated from the admin cookie and is never selected by the admin authenticator.

## Rollout dependency

Deploy the additive `fiducia-auth` producer PR before this consumer. During a mixed-version rollout, an old auth replica does not return `authorization`; this admin build rejects that response instead of silently falling back to raw roles. Use normal rolling-deployment readiness and drain behavior to keep traffic on compatible auth replicas.

## Deliberate follow-up

This PR establishes the receiving-surface gate and normalized role/capability contract. DEN-253 remains open for a route-by-route capability matrix that distinguishes read, operate, and write handlers; explicit dual-surface administration workflow; migration inventory; removal of the temporary legacy-customer compatibility shape; and end-to-end negative tests across auth, customer, admin, edge, and proxies.
