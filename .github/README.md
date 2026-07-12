# .github — CI/CD and repo automation

GitHub configuration for `fiducia-admin`: the Actions workflows that build, test,
and deploy the service, plus dependency automation.

- **`workflows/`** — the CI/CD pipelines (build/test, Docker image publish,
  test-environment deploy).
- **`dependabot.yml`** — weekly dependency update PRs for both the Cargo crates
  and the GitHub Actions used by the workflows.
