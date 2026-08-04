# Admin Shared Auth cutover

The admin application uses its own Supabase project only as the upstream identity provider. A provider access token is not an admin authorization credential by itself.

## Runtime boundary

The process requires `SHARED_AUTH_URL`, `SHARED_AUTH_ISSUER`, `SHARED_AUTH_AUDIENCE`, `SHARED_AUTH_INTROSPECT_SECRET`, and the admin plane's `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`.

The guard is pinned to provider project `fiducia-admin` and accepts only Shared Auth roles `admin` or `operator`. Direct Supabase verification participates only as an identity-resilience arm; it never grants dashboard access and never produces a browser session upgrade.

After password authentication, Shared Auth must win the exchange/introspection race. The application persists only the returned Shared Auth access token in the host-only HttpOnly admin cookie. Customer-project tokens, role-less provider tokens, and already-valid Shared Auth JWTs presented to the password-login endpoint without a new session upgrade fail closed.

## Local authorization

A Shared Auth role is necessary but not sufficient. The pinned Supabase subject must also match an enabled local `operators` row. Local roles `owner`, `admin`, and `operator` may operate; `viewer`, missing, and disabled rows are denied.

## Request behavior

Explicit Authorization credentials take precedence over ambient cookies. Duplicate or malformed Authorization headers and duplicate admin cookies are rejected. Existing Shared Auth cookies are verified locally through bounded, cached ES256 JWKS; a customer-project JWT cannot cross into the admin plane even when it carries an overlapping role name.

## Rollout

1. Deploy Shared Auth with the distinct `fiducia-admin` Supabase provider configuration.
2. Provision the Shared Auth issuer, audience, introspection secret, and admin Supabase values in the admin secret plane.
3. Apply the application release.
4. Verify login rotates the provider token to a Shared Auth cookie.
5. Verify customer-project, missing-role, disabled-operator, and no-upgrade negative cases.
6. Remove `FIDUCIA_AUTH_URL` from deployment configuration after rollback observation completes; the application no longer reads it.

## Pull-request validation

Every cutover update is validated by the normal read-only workflow: Rust formatting, Clippy, unit and integration tests, dependency audit, production-container construction, and the real-browser dual-auth journeys. The build-artifact workflow used during implementation has read-only repository permission and is deleted before merge.
