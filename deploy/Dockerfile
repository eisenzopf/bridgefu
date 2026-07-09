# bridgefu — multi-stage build.
#
# The build CONTEXT is the bridgefu repo root; the Dockerfile lives at
# deploy/Dockerfile. Build from the repo root with:
#
#     docker build -t bridgefu:latest -f deploy/Dockerfile .
#
# bridgefu depends on rvoip-amazon-connect from crates.io (Cargo.toml pins
# `rvoip-amazon-connect = "0.1.2"`, which pulls rvoip-webrtc 0.1.2 + the 0.2.4
# beta train). Cargo fetches the whole tree from the registry, so there is no
# rvoip checkout to copy or clone — just this repo.

# ---- builder ----------------------------------------------------------------
# NOTE: the resolved dependency tree's rustc floor is set by the AWS SDK crates
# (aws-smithy-*, aws-types) in our Cargo.lock, which require rustc >= 1.91.1.
# Pin to 1.95 (matches the dev host). bookworm → glibc, matched by the
# debian-slim runtime stage.
FROM rust:1.95-bookworm AS builder

# Build deps the rvoip dependency tree needs (compiled from crates.io source):
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

WORKDIR /src/bridgefu
# Copy the repo. `.dockerignore` keeps target/, .git/, and logs out.
COPY . /src/bridgefu
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
