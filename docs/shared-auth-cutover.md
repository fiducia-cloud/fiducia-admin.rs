# Admin Shared Auth cutover

The admin application uses its own Supabase project only as the upstream identity provider. A provider access token is not an admin authorization credential by itself.

## Runtime boundary

The process requires:

- `SHARED_AUTH_URL`
- `SHARED_AUTH_ISSUER`
- `SHARED_AUTH_AUDIENCE`
- `SHARED_AUTH_INTROSPECT_SECRET`
- the admin plane's `SUPABASE_URL`
- the admin plane's `SUPABASE_PUBLISHABLE_KEY`

The guard is pinned to provider project `fiducia-admin` and accepts only Shared Auth roles `admin` or `operator`. Direct Supabase verification participates only as an identity-resilience arm; it never grants dashboard access and never produces a browser session upgrade.

After password authentication, Shared Auth must win the exchange/introspection race. The application persists only the returned Shared Auth access token in the host-only HttpOnly admin cookie. Customer-project tokens and role-less provider tokens fail closed.

## Local authorization

A Shared Auth role is necessary but not sufficient. The Supabase subject must also match an enabled local `operators` row. Local roles `owner`, `admin`, and `operator` may operate; `viewer`, missing, and disabled rows are denied.

## Rollout

1. Deploy Shared Auth with the distinct `fiducia-admin` Supabase provider configuration.
2. Provision the Shared Auth issuer, audience, introspection secret, and admin Supabase values in the admin secret plane.
3. Apply the application release.
4. Verify login rotates the provider token to a Shared Auth cookie.
5. Verify customer-project and disabled-operator negative cases.
6. Remove `FIDUCIA_AUTH_URL` from the admin deployment after rollback observation completes.

The pull request's generated lockfile and formatting are produced from the exact pinned sibling graph before review. A documentation-only synchronization commit activates the one-time, PR-scoped cutover helper; the resulting feature commit restores the normal read-only CI workflow.
