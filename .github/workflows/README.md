# .github/workflows — CI/CD pipelines

GitHub Actions for `fiducia-admin`. This repository tests the service and
publishes deployable artifacts; it does not mutate an environment.

- **`ci.yml`** — checks out the repo alongside exact, reviewed
  `fiducia-interfaces` and `fiducia-sync` commits, then runs locked `cargo fmt`,
  `clippy`, `test`, and a pinned `cargo-audit`.
- **`docker.yml`** — on `main`, builds the container and publishes only its
  immutable commit-SHA tag, with maximum BuildKit provenance and an SBOM. The
  same immutable sibling commits are passed as explicit Docker build arguments.

Kubernetes credentials and deployment logic belong only to `fiducia-monorepo`.

## Security baseline

Every executable workflow uses explicit least-privilege permissions, immutable
third-party action or container references, non-persisted checkout credentials,
concurrency control, and a job timeout. The main CI workflow validates this
directory with the digest-pinned actionlint container. Environment mutation is
forbidden unless this README documents a repository-specific platform exception.
