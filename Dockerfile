# syntax=docker/dockerfile:1
# =============================================================================
# Stage 1: Builder (Debian 12 Bookworm + Rust stable for Edition 2024)
# =============================================================================
FROM rust:bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        cmake \
        libclang-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/wolin

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --locked --release -p wolin-server \
    && test "$(stat -c%s /usr/src/wolin/target/release/wolin-server)" -lt 41943040

# =============================================================================
# Stage 2: Minimal Hardened Runtime (Debian 12 Bookworm Slim)
# =============================================================================
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="wolin-server" \
      org.opencontainers.image.description="Wolin (月印千江) — Sovereign W3C Solid 0.11 Pod + WAC/ACP + Native MCP Server" \
      org.opencontainers.image.source="https://github.com/wolin-id/wolin" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 wolin \
    && useradd --system --uid 10001 --gid wolin --home-dir /data --no-create-home --shell /usr/sbin/nologin wolin \
    && install -d -m 0700 -o wolin -g wolin /data

COPY --from=builder --chown=root:root /usr/src/wolin/target/release/wolin-server /usr/local/bin/wolin-server

ENV WOLIN_LISTEN_ADDR=0.0.0.0:4000 \
    WOLIN_STORAGE_DIR=/data \
    WOLIN_LOG=info,wolin_server=info,wolin_mcp=info,tower_http=info

VOLUME ["/data"]
EXPOSE 4000
USER wolin:wolin
WORKDIR /data

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/wolin-server", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/wolin-server"]
