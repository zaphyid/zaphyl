<p align="center">
  <img src="assets/logo.png" alt="Zaphyl" width="200" />
</p>

<p align="center">
  <strong>A memory-safe HTTP/1·2·3 reverse proxy and web server, written in Rust on
  Cloudflare's <a href="https://github.com/cloudflare/pingora">Pingora</a>.</strong>
</p>

One binary terminates HTTP/1.1, HTTP/2, and HTTP/3 (QUIC), obtains and renews its
own TLS certificates, load-balances to your upstreams, and is extensible with
sandboxed WebAssembly plugins.

> **Status: `0.1.0`, early.** Zaphyl is feature-complete enough to be useful but
> has **no production track record** and has not been independently audited.
> Try it, report issues - don't put it in front of critical traffic yet. See
> [SECURITY.md](SECURITY.md) for the security posture and known limitations.

## Features

- **All three HTTP versions in one binary** - HTTP/1.1, HTTP/2, and HTTP/3
  (QUIC) including replay-safe 0-RTT. HTTP/2 and gRPC upstreams are supported.
- **Automatic HTTPS** - obtain and renew certificates over ACME (Let's Encrypt),
  or supply your own. Certificates hot-reload without a restart.
- **Reverse proxy** - host/path routing, round-robin load balancing, passive
  health checks, path-prefix rewriting, and per-route request/response headers.
- **WebSocket and gRPC** pass-through.
- **Response compression** - gzip, brotli, and zstd, negotiated per client, on
  both the HTTP/1·2 and HTTP/3 paths.
- **Response caching** - `Vary`-aware, `ETag`/`304` revalidation, an optional
  disk tier, and conditional origin revalidation.
- **Static file serving**, traversal-safe.
- **Access control** by client IP/CIDR, per-IP **rate limiting**, and Prometheus
  **metrics**.
- **WebAssembly plugins** - write request/response filters in any language that
  compiles to a WASM component; they run sandboxed (no host access, with
  execution-time and memory limits), attachable globally and per route.
- **Memory-safe** - `unsafe` is forbidden across the codebase.

## Install

Every release publishes prebuilt artifacts. Pick whichever fits your platform:

**Container (any distro/version, and Windows via Docker Desktop):**

```sh
docker run --rm -p 8080:8080 -v "$PWD/zaphyl.toml:/etc/zaphyl/zaphyl.toml" \
  ghcr.io/zaphyid/zaphyl:latest
```

**Debian / Ubuntu:** download the `.deb` from the
[releases page](https://github.com/zaphyid/zaphyl/releases), then:

```sh
sudo dpkg -i zaphyl_*.deb
sudo systemctl enable --now zaphyl   # after editing /etc/zaphyl/zaphyl.toml
```

**RHEL / Fedora / SUSE:** download the `.rpm` and `sudo rpm -i zaphyl-*.rpm`
(also installs the `zaphyl` systemd service).

**Linux binary (x86_64 / aarch64, glibc 2.36+):** download the
`zaphyl-<version>-<arch>-linux.tar.gz` from the
[releases page](https://github.com/zaphyid/zaphyl/releases), extract, and run
`./zaphyl --config zaphyl.toml`. On Alpine/musl or older distributions, use the
container image instead.

**Windows:** run the container with Docker Desktop, or build and run under WSL2.
Zaphyl is built on Pingora, which is Linux-only, so there is no native Windows
binary.

**From source** (needs stable Rust, MSRV 1.94):

```sh
cargo build --release
```

## Quickstart

Write a minimal config, `zaphyl.toml`:

```toml
listen = "0.0.0.0:8080"

[[route]]
upstream = "127.0.0.1:3000"
```

Run it:

```sh
./target/release/zaphyl --config zaphyl.toml
```

Zaphyl now forwards everything on `:8080` to `127.0.0.1:3000`.

## Configuration

See [`zaphyl.example.toml`](zaphyl.example.toml) for a fully commented config
covering TLS/ACME, HTTP/3, routing, caching, compression, access control,
metrics, plugins, and limits. A few common cases:

**Automatic HTTPS with HTTP/3:**

```toml
listen = "0.0.0.0:443"

[acme]
domains = ["example.com"]
email   = "you@example.com"

[http3]
listen = "0.0.0.0:443"   # QUIC, over UDP

[http]
listen = "0.0.0.0:80"    # redirect to HTTPS + serve ACME challenges

[[route]]
host     = "example.com"
upstream = ["10.0.0.1:8000", "10.0.0.2:8000"]   # round-robin
```

**A route with a WASM plugin:**

```toml
[[route]]
path     = "/api"
upstream = "127.0.0.1:9000"
plugins  = ["./plugins/auth.wasm"]
```

## Plugins

Plugins are WebAssembly **components** built against the WIT contract in
[`crates/zaphyl-plugin/wit/`](crates/zaphyl-plugin/wit/). A plugin implements
`handle-request` (which may rewrite the request or short-circuit with a response)
and `handle-response`. They run in a Wasmtime sandbox with no ambient authority,
a wall-clock deadline, and a memory cap. See
[`test-plugins/filter`](test-plugins/filter) for a working example.

## Benchmarks

[`benchmarks/`](benchmarks) holds a reproducible reverse-proxy benchmark against
nginx and Caddy, with honest caveats. On the recorded run Zaphyl forwards faster
than Caddy and within ~2× of nginx for HTTP/1.1 - but read the caveats before
quoting any number.

## Building and testing

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --all-targets --workspace -- -D warnings
```

## License

[Apache-2.0](LICENSE).
