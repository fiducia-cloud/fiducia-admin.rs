# scripts

- **`with-flags2env.sh`** translates audited non-secret CLI flags into this
  service's environment variables.
- **`dpm-schema.sh`** is the operator-side declarative migration workflow for
  the isolated admin database. It uses the canonical
  `fiducia-interfaces/sql/admin.sql` source, offers reviewable `diff` and
  shadow-proven `verify`, and requires `DPM_APPLY_APPROVED=1` before `apply`.
