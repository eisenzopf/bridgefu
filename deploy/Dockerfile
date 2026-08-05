# syntax=docker/dockerfile:1.7
# Canonical Bridgefu image. The committed Cargo.lock is the complete source of
# truth for the immutable rvoip 0.3.5 dependency graph:
#
#   docker build -f deploy/Dockerfile .
#
# Both base references are multi-platform manifest-list digests. Updating one
# is an intentional supply-chain change and must be accompanied by a CI build
# for linux/amd64 and linux/arm64.
ARG RUST_IMAGE=docker.io/library/rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot@sha256:d97bc0a941b8d4be647dc0ee75b264ddbb772f1ac5ba690a4309c00723b23775
ARG BUILDER_DEBIAN_SNAPSHOT=20260518T000000Z

FROM ${RUST_IMAGE} AS build-base

ARG BUILDER_DEBIAN_SNAPSHOT
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN sed -i \
        -e "s|URIs: http://deb.debian.org/debian-security|URIs: http://snapshot.debian.org/archive/debian-security/${BUILDER_DEBIAN_SNAPSHOT}|" \
        -e "s|URIs: http://deb.debian.org/debian|URIs: http://snapshot.debian.org/archive/debian/${BUILDER_DEBIAN_SNAPSHOT}|" \
        /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' \
        > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential=12.9 \
        clang=1:14.0-55.7~deb12u1 \
        cmake=3.25.1-1 \
        libclang-dev=1:14.0-55.7~deb12u1 \
        pkg-config=1.8.1-1 \
        protobuf-compiler=3.21.12-3 \
    && rm -rf /var/lib/apt/lists/*

COPY . /src/bridgefu
WORKDIR /src/bridgefu

FROM build-base AS builder

RUN cargo build --locked --release \
    && install -D -m 0755 target/release/bridgefu /out/bridgefu \
    && strip /out/bridgefu \
    && install -d -m 0750 /out/var/lib/bridgefu \
    && rm -rf target /usr/local/cargo/registry /usr/local/cargo/git

FROM ${RUNTIME_IMAGE} AS runtime

ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Bridgefu" \
      org.opencontainers.image.description="Programmable SIP, WebRTC, and QUIC audio bridge" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/eisenzopf/bridgefu" \
      org.opencontainers.image.version="0.9.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.rvoip.version="0.3.5" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=builder --chown=65532:65532 /out/bridgefu /usr/local/bin/bridgefu
COPY --from=builder --chown=65532:65532 /out/var/lib/bridgefu/ /var/lib/bridgefu/

USER 65532:65532
EXPOSE 5060/tcp 5060/udp 5070/tcp 5070/udp \
       8080/tcp 8081/tcp 9080/tcp 9090/tcp 40000/udp \
       16384-32767/udp 4433/udp 4443/udp 4444/udp 4445/udp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/bridgefu", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/bridgefu"]
CMD ["--config", "/etc/bridgefu/bridgefu.yaml"]
