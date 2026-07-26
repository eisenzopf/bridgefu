# syntax=docker/dockerfile:1.7
# Build with the exact reviewed rvoip checkout:
# docker build --build-context rvoip=../rvoip -f deploy/vapi-feasibility/Dockerfile .
ARG RUST_IMAGE=docker.io/library/rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG BUILDER_DEBIAN_SNAPSHOT=20260518T000000Z
ARG RUNTIME_DEBIAN_SNAPSHOT=20260713T000000Z

FROM scratch AS rvoip
COPY deploy/missing-rvoip-context /.bridgefu-missing-rvoip-build-context

FROM ${RUST_IMAGE} AS builder
ARG BUILDER_DEBIAN_SNAPSHOT
RUN sed -i \
        -e "s|URIs: http://deb.debian.org/debian-security|URIs: http://snapshot.debian.org/archive/debian-security/${BUILDER_DEBIAN_SNAPSHOT}|" \
        -e "s|URIs: http://deb.debian.org/debian|URIs: http://snapshot.debian.org/archive/debian/${BUILDER_DEBIAN_SNAPSHOT}|" \
        /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
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
    && cargo build --locked --release --example vapi_feasibility_observer \
    && install -D -m 0755 \
        target/release/examples/vapi_feasibility_observer \
        /out/vapi-feasibility-observer \
    && strip /out/vapi-feasibility-observer

FROM ${RUNTIME_IMAGE} AS runtime
ARG RUNTIME_DEBIAN_SNAPSHOT
RUN sed -i \
        -e "s|URIs: http://deb.debian.org/debian-security|URIs: http://snapshot.debian.org/archive/debian-security/${RUNTIME_DEBIAN_SNAPSHOT}|" \
        -e "s|URIs: http://deb.debian.org/debian|URIs: http://snapshot.debian.org/archive/debian/${RUNTIME_DEBIAN_SNAPSHOT}|" \
        /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
        curl=7.88.1-10+deb12u15 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 65532 fixture \
    && useradd --system --uid 65532 --gid 65532 \
        --home-dir /nonexistent --shell /usr/sbin/nologin fixture
COPY --from=builder /out/vapi-feasibility-observer /usr/local/bin/
USER 65532:65532
EXPOSE 9088/tcp 9443/tcp 5061/tcp 30000-30031/udp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
  CMD ["sh", "-c", "curl --fail --silent --show-error --insecure \"${VAPI_FIXTURE_HEALTH_URL:-http://127.0.0.1:9088/livez}\" >/dev/null"]
ENTRYPOINT ["/usr/local/bin/vapi-feasibility-observer"]
