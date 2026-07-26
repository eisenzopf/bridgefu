# syntax=docker/dockerfile:1.7
# Canonical Bridgefu image. The named `rvoip` build context must be the exact
# reviewed checkout that matches Cargo.lock:
#
#   docker build --build-context rvoip=../rvoip -f deploy/Dockerfile .
#
# Both base references are multi-platform manifest-list digests. Updating one
# is an intentional supply-chain change and must be accompanied by a CI build
# for linux/amd64 and linux/arm64.
ARG RUST_IMAGE=docker.io/library/rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG BUILDER_DEBIAN_SNAPSHOT=20260518T000000Z
ARG RUNTIME_DEBIAN_SNAPSHOT=20260713T000000Z

# A named build context overrides a same-named stage. Without
# `--build-context rvoip=...`, this local sentinel stage is used so Docker never
# interprets `rvoip` as a floating registry image.
FROM scratch AS rvoip
COPY deploy/missing-rvoip-context /.bridgefu-missing-rvoip-build-context

FROM ${RUST_IMAGE} AS builder

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

COPY --from=rvoip . /src/rvoip
COPY . /src/bridgefu
WORKDIR /src/bridgefu

RUN if test -e /src/rvoip/.bridgefu-missing-rvoip-build-context; then \
        echo 'missing required --build-context rvoip=/exact/reviewed/checkout' >&2; \
        exit 64; \
    fi \
    && cargo build --locked --release \
    && install -D -m 0755 target/release/bridgefu /out/bridgefu \
    && strip /out/bridgefu

FROM ${RUNTIME_IMAGE} AS runtime

ARG RUNTIME_DEBIAN_SNAPSHOT
ARG VCS_REF=unknown
ARG RVOIP_REVISION=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Bridgefu" \
      org.opencontainers.image.description="Programmable SIP, WebRTC, and QUIC audio bridge" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.rvoip.revision="${RVOIP_REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}"

RUN sed -i \
        -e "s|URIs: http://deb.debian.org/debian-security|URIs: http://snapshot.debian.org/archive/debian-security/${RUNTIME_DEBIAN_SNAPSHOT}|" \
        -e "s|URIs: http://deb.debian.org/debian|URIs: http://snapshot.debian.org/archive/debian/${RUNTIME_DEBIAN_SNAPSHOT}|" \
        /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' \
        > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
        curl=7.88.1-10+deb12u15 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 65532 bridgefu \
    && useradd --system --uid 65532 --gid 65532 \
        --home-dir /nonexistent --shell /usr/sbin/nologin bridgefu \
    && install -d -o 65532 -g 65532 -m 0750 /var/lib/bridgefu

COPY --from=builder /out/bridgefu /usr/local/bin/bridgefu

USER 65532:65532
EXPOSE 5060/tcp 5060/udp 5070/tcp 5070/udp \
       8080/tcp 8081/tcp 9080/tcp 9090/tcp 40000/udp \
       16384-32767/udp 4433/udp 4443/udp 4444/udp 4445/udp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD ["curl", "--fail", "--silent", "http://127.0.0.1:9090/livez"]

ENTRYPOINT ["/usr/local/bin/bridgefu"]
CMD ["--config", "/etc/bridgefu/bridgefu.yaml"]
