# .nix — reproducible dev environment

The Nix flake that pins this repo's development shell. `flake.nix` defines a
`devShell` (across the four Linux/macOS systems) with the Rust toolchain
(rustc, cargo, rustfmt, clippy, rust-analyzer, bacon) plus Node/pnpm for the
browser E2E and the `openssl`/`pkg-config` needed to build. `flake.lock` pins
the exact nixpkgs revision for reproducibility.

Entered via the repo-root `shell` script (`nix develop ./.nix`), typically
through direnv. This is developer tooling only — it is not part of the shipped
container image (see the `Dockerfile`).
