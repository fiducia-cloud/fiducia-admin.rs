# .github/workflows — CI/CD pipelines

GitHub Actions for `fiducia-admin`. Together they gate merges and ship the
service: build and check on every push/PR, then on `main` publish an image and
roll the test environment.

- **`ci.yml`** — checks out the repo alongside exact, reviewed
  `fiducia-interfaces` and `fiducia-sync` commits, then runs locked `cargo fmt`,
  `clippy`, `test`, and a pinned `cargo-audit`.
- **`docker.yml`** — on `main`, builds the container and pushes it to
  `ghcr.io/fiducia-cloud/fiducia-admin` tagged `latest` and the commit SHA. The
  same immutable sibling commits are passed as explicit Docker build arguments.
- **`deploy-test.yml`** — on `main`, rolls the `fiducia-test` Kubernetes
  namespace to the SHA-tagged image. `KUBE_CONFIG_TEST` is mandatory: missing,
  invalid, or empty credentials fail the job, as do a missing target and an
  incomplete rollout. App repos deploy to TEST from their own CI; PROD deploys
  only from the monorepo.
