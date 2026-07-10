# syntax=docker/dockerfile:1.7
# Build with: docker build --build-context rvoip=../rvoip -t bridgefu .
FROM rust:1.95-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang cmake libclang-dev pkg-config protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rvoip . /src/rvoip
COPY . /src/bridgefu
WORKDIR /src/bridgefu
RUN cargo build --locked --release \
    && install -m 0755 target/release/bridgefu /out/bridgefu \
    && strip /out/bridgefu

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 65532 bridgefu \
    && useradd --system --uid 65532 --gid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin bridgefu
COPY --from=builder /out/bridgefu /usr/local/bin/bridgefu

USER 65532:65532
EXPOSE 5060/tcp 5060/udp 5070/tcp 5070/udp 8080/tcp 8081/tcp 9090/tcp 4433/udp 4443/udp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD ["curl", "--fail", "--silent", "http://127.0.0.1:9090/livez"]
ENTRYPOINT ["/usr/local/bin/bridgefu"]
CMD ["--config", "/etc/bridgefu/bridgefu.yaml"]
