# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-admin.
FROM rust:1.97.0-slim-bookworm@sha256:cfbb0e0ef7a73e736386bfa346f1cb0503c6d162969dc9426fb37834f3f64c25 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
ARG INTERFACES_REF=bbd8b52ce729ec34b0a9bff4dda6d0a448181797
ARG SYNC_REF=5d3660511b3bfe951d0a66f9d7737497e0d1401f
RUN test "${#INTERFACES_REF}" -eq 40 \
    && case "$INTERFACES_REF" in *[!0-9a-f]*) exit 1;; esac \
    && git init fiducia-interfaces \
    && git -C fiducia-interfaces remote add origin https://github.com/fiducia-cloud/fiducia-interfaces.git \
    && git -C fiducia-interfaces fetch --depth 1 origin "$INTERFACES_REF" \
    && git -C fiducia-interfaces checkout --detach FETCH_HEAD \
    && test "$(git -C fiducia-interfaces rev-parse HEAD)" = "$INTERFACES_REF"
RUN test "${#SYNC_REF}" -eq 40 \
    && case "$SYNC_REF" in *[!0-9a-f]*) exit 1;; esac \
    && git init fiducia-sync \
    && git -C fiducia-sync remote add origin https://github.com/fiducia-cloud/fiducia-sync.git \
    && git -C fiducia-sync fetch --depth 1 origin "$SYNC_REF" \
    && git -C fiducia-sync checkout --detach FETCH_HEAD \
    && test "$(git -C fiducia-sync rev-parse HEAD)" = "$SYNC_REF"
COPY . fiducia-admin.rs
WORKDIR /build/fiducia-admin.rs
RUN cargo build --release --locked && strip target/release/fiducia-admin

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:ce0d66bc0f64aae46e6a03add867b07f42cc7b8799c949c2e898057b7f75a151
COPY --from=build --chown=65532:65532 /build/fiducia-admin.rs/target/release/fiducia-admin /usr/local/bin/fiducia-admin
EXPOSE 8096
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fiducia-admin"]
