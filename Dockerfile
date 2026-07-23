# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-admin.
FROM rust:1.97.0-slim-bookworm@sha256:6d220bf85c74e842a79da63997af8d2e74455c0b8847d8bb3a5888572334991d AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
ARG INTERFACES_REF=487e470c45ab5851e8f6f3b1dc048fe067fbf408
ARG SYNC_REF=b9545140932995f75af8b3c5514cb4379404264c
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

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e
COPY --from=build --chown=65532:65532 /build/fiducia-admin.rs/target/release/fiducia-admin /usr/local/bin/fiducia-admin
EXPOSE 8096
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fiducia-admin"]
