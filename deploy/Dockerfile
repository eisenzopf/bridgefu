# bridgefu — multi-stage build.
#
# IMPORTANT: the build CONTEXT is the PARENT directory that holds *both* repos:
#
#     /opt/build/rvoip      <- git clone https://github.com/eisenzopf/rvoip
#     /opt/build/bridgefu   <- this repo (Dockerfile is bridgefu/deploy/Dockerfile)
#
# Build with:
#     docker build -t bridgefu:latest -f bridgefu/deploy/Dockerfile /opt/build
#
# bridgefu/Cargo.toml depends on rvoip-amazon-connect by the relative path
# `../rvoip/crates/webrtc/rvoip-amazon-connect`. We copy both trees so that the
# same `../rvoip` path resolves inside the image — no Cargo.toml edits, and we
# never touch crates.io (some rvoip crates are unpublished).

# ---- builder ----------------------------------------------------------------
# NOTE: the rvoip workspace declares rust-version = 1.88, but the resolved
# dependency tree floor is higher — the AWS SDK crates (aws-smithy-*, aws-types)
# in our Cargo.lock require rustc >= 1.91.1. Pin to 1.95 (matches the dev host).
# bookworm → glibc, matched by the debian-slim runtime stage.
FROM rust:1.95-bookworm AS builder

# Build deps the rvoip tree needs:
#  - protobuf-compiler: rvoip-amazon-connect build.rs (prost-build) needs protoc
#  - cmake + clang + libclang-dev: media-core `opus` feature builds libopus
#    (audiopus_sys) via cmake and generates bindings with bindgen/libclang
#  - build-essential + pkg-config: C toolchain for ring/AWS SDK/etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        cmake \
        clang \
        libclang-dev \
        build-essential \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Copy both trees. `.dockerignore` (bridgefu/.dockerignore) keeps target/ out.
COPY rvoip /src/rvoip
COPY bridgefu /src/bridgefu

WORKDIR /src/bridgefu
# Release build uses bridgefu's own [profile.release] (thin LTO, opt-level 2),
# which governs the whole dependency tree.
RUN cargo build --release \
    && cp target/release/bridgefu /usr/local/bin/bridgefu \
    && strip /usr/local/bin/bridgefu

# ---- runtime ----------------------------------------------------------------
# Slim glibc base; ca-certificates for rustls/webpki (Chime WSS + AWS SDK TLS).
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/bridgefu /usr/local/bin/bridgefu

# Config is bind-mounted at /etc/bridgefu by the systemd unit / `docker run`.
ENTRYPOINT ["/usr/local/bin/bridgefu"]
CMD ["--config", "/etc/bridgefu/bridgefu.yaml"]
