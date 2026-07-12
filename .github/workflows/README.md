# .github/workflows — CI/CD pipelines

GitHub Actions for `fiducia-admin`. Together they gate merges and ship the
service: build and check on every push/PR, then on `main` publish an image and
roll the test environment.

- **`ci.yml`** — checks out the repo alongside `fiducia-interfaces` (a path
  dependency), then runs `cargo fmt`, `clippy`, `test`, and `cargo audit`.
- **`docker.yml`** — on `main`, builds the container and pushes it to
  `ghcr.io/fiducia-cloud/fiducia-admin` tagged `latest` and the commit SHA.
- **`deploy-test.yml`** — on `main`, rolls the `fiducia-test` Kubernetes
  namespace to the SHA-tagged image. Secret-gated on `KUBE_CONFIG_TEST`; a no-op
  (validation-only) when the secret is absent. App repos deploy to TEST from
  their own CI; PROD deploys only from the monorepo.
