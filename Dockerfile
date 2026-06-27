# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-admin (telemetry is a git cargo dep — fetched at build).
FROM rust:1-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/fiducia-admin.rs
COPY . .
RUN cargo build --release && strip target/release/fiducia-admin

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/fiducia-admin.rs/target/release/fiducia-admin /usr/local/bin/fiducia-admin
EXPOSE 8096
ENTRYPOINT ["/usr/local/bin/fiducia-admin"]
