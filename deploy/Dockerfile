# syntax=docker/dockerfile:1.7
# Canonical Bridgefu image. The committed Cargo.lock is the complete source of
# truth for the revision-pinned rvoip 0.5.0 TURN candidate dependency graph:
#
#   docker build -f deploy/Dockerfile .
#
# All base references are multi-platform manifest-list digests. Updating one
# is an intentional supply-chain change and must be accompanied by a CI build
# for linux/amd64 and linux/arm64.
ARG RUST_IMAGE=docker.io/library/rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1
ARG CC_IMAGE=gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de
ARG RUNTIME_IMAGE=gcr.io/distroless/base-nossl-debian13:nonroot@sha256:4006ac92504be607b70de01d1f64f38288c69fcd8faa820f6d3aed266ea32ac5
ARG BUILDER_DEBIAN_SNAPSHOT=20260518T000000Z

FROM ${CC_IMAGE} AS cc-runtime

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

# Retain only the C/C++ runtime libraries used by the Rust/native-code graph.
# OpenSSL, zlib, and zstd from the cc image are not runtime dependencies.
# Keep Debian package metadata and licenses with the selected libraries.
COPY --from=cc-runtime /usr/lib/ /runtime-packages/usr/lib/
COPY --from=cc-runtime /var/lib/dpkg/status.d/ /runtime-packages/var/lib/dpkg/status.d/
COPY --from=cc-runtime /usr/share/doc/ /runtime-packages/usr/share/doc/
RUN mkdir -p /out/runtime-libs \
    && cd /runtime-packages \
    && cp -a --parents \
        usr/lib/*-linux-gnu/libgcc_s.so.1 \
        usr/lib/*-linux-gnu/libstdc++.so.6* \
        var/lib/dpkg/status.d/libgcc-s1* \
        var/lib/dpkg/status.d/libstdc++6* \
        var/lib/dpkg/status.d/gcc-14-base* \
        usr/share/doc/libgcc-s1 \
        usr/share/doc/libstdc++6 \
        usr/share/doc/gcc-14-base \
        /out/runtime-libs/

COPY . /src/bridgefu
WORKDIR /src/bridgefu

RUN cargo build --locked --release \
    && install -D -m 0755 target/release/bridgefu /out/bridgefu \
    && strip /out/bridgefu \
    && install -d -m 0750 /out/var/lib/bridgefu

FROM ${RUNTIME_IMAGE} AS runtime

ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Bridgefu" \
      org.opencontainers.image.description="Programmable SIP, WebRTC, and QUIC audio bridge" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/eisenzopf/bridgefu" \
      org.opencontainers.image.version="0.9.1" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.rvoip.version="0.5.0" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=builder /out/runtime-libs/ /
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
