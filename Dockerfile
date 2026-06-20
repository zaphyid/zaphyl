# Build stage. Zaphyl links BoringSSL (via Pingora), which needs cmake, clang,
# and Go to build.
FROM rust:1-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang libclang-dev golang pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release --bin zaphyl

# Runtime stage. BoringSSL is statically linked, so the runtime only needs CA
# certificates (for upstream TLS and ACME).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/zaphyl /usr/local/bin/zaphyl
# Default config + welcome page, so a bare `docker run` shows the server is up.
# Mount your own config over /etc/zaphyl/zaphyl.toml to replace it.
COPY web/index.html /usr/share/zaphyl/html/index.html
COPY packaging/default.toml /etc/zaphyl/zaphyl.toml

# HTTP/3 needs the HTTPS port published over UDP as well as TCP.
EXPOSE 80/tcp 443/tcp 443/udp

ENTRYPOINT ["/usr/local/bin/zaphyl", "--config", "/etc/zaphyl/zaphyl.toml"]
