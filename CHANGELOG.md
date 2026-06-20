# Changelog

All notable changes to Zaphyl are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [1.0.2] - 2026-06-19

First tagged release - a memory-safe HTTP/1·2·3 reverse proxy on Pingora.

### Added

- HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) in a single binary; HTTP/3 includes
  replay-safe 0-RTT early data.
- Automatic HTTPS via ACME (Let's Encrypt) with automatic renewal, alongside
  static certificates; both hot-reload without a restart.
- Reverse proxy: host/path routing, round-robin load balancing, passive health
  checks, path-prefix rewriting, and per-route request/response headers.
- WebSocket and gRPC (HTTP/2 upstream) pass-through.
- Response compression - gzip, brotli, and zstd - on both the HTTP/1·2 and
  HTTP/3 paths, negotiated per client.
- Response caching: `Vary`-aware, `ETag`/`304` revalidation, an optional disk
  tier, and conditional origin revalidation.
- Static file serving.
- IP/CIDR access control, per-IP rate limiting, and Prometheus metrics.
- A sandboxed WebAssembly plugin system (Wasmtime Component Model) with global
  and per-route chains, request and response hooks, and execution-time and
  memory limits.
- Multi-threaded request forwarding by default, configurable via
  `worker_threads`.
- Graceful shutdown on `SIGTERM` with a short, configurable grace period
  (`shutdown_grace_seconds`, default 5) so the server stops promptly under
  Docker and Kubernetes.
- Automated release pipeline: each version tag publishes Linux binaries
  (x86_64 and aarch64), `.deb` and `.rpm` packages with a hardened systemd unit
  and a built-in welcome page, and a multi-arch container image on GHCR.

### Security

- `unsafe` is forbidden across the workspace.
- Request bodies and (on HTTP/3) header sections are size-bounded; the on-disk
  cache decoder bounds every allocation against the data actually present.

[1.0.2]: https://github.com/zaphyid/zaphyl/releases/tag/v1.0.2
