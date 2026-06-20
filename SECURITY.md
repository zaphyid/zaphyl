# Security Policy

Zaphyl is a reverse proxy: it sits in front of other services and terminates
untrusted traffic. Security is a primary goal, not an afterthought.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's [private vulnerability reporting][gh-report]
(the **Report a vulnerability** button under the repository's **Security** tab).
This opens a private advisory visible only to the maintainers.

We aim to acknowledge a report within 72 hours, agree on a disclosure timeline,
and credit reporters who wish to be named once a fix is released.

[gh-report]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

## Supported versions

Zaphyl is pre-1.0 and under active development. Security fixes land on `main`
and in the latest release. Until 1.0, only the most recent release is supported.

## Security posture

What the codebase does to limit its attack surface:

- **Memory safety.** `unsafe` code is forbidden across the workspace
  (`unsafe_code = "forbid"`); memory-safety bugs in dependencies are the only
  remaining vector, and the dependency set is audited (below).
- **Sandboxed plugins.** WASM plugins run in a Wasmtime sandbox with no ambient
  authority, a wall-clock execution deadline, and a hard memory cap, so a buggy
  or hostile plugin cannot read host memory, block the event loop, or exhaust
  RAM.
- **Bounded inputs.** Request bodies and (on HTTP/3) the decoded header section
  are size-limited; the on-disk cache decoder bounds every allocation against
  the data actually present, so a corrupt entry cannot trigger a huge allocation.
- **Replay-safe 0-RTT.** HTTP/3 0-RTT early data is accepted only for safe
  (idempotent) methods; unsafe early-data requests get `425 Too Early`, and safe
  ones are forwarded with `Early-Data: 1` (RFC 8470).
- **TLS.** TLS 1.3 on HTTP/3 (QUIC requires it) via rustls, and TLS 1.2/1.3 on
  HTTP/1·2 via BoringSSL; upstream certificates are verified against the system
  roots plus any configured CA. No "accept invalid certificate" path exists.
- **Supply chain.** CI runs `cargo-deny` (RUSTSEC advisories, license policy,
  and source allow-listing) on every change.

## Known limitations (pre-1.0)

Stated plainly so operators can compensate:

- **No production track record.** Zaphyl has not yet handled real traffic at
  scale or been independently audited. Treat it accordingly.
- **No global connection cap.** The HTTP/3 listener relies on QUIC idle timeouts
  and per-connection stream limits plus the operating system's file-descriptor
  limits; there is no built-in ceiling on concurrent connections. Front it with
  OS limits or a network-level rate limiter in hostile environments.
- **Rate limiting is per-process.** The built-in limiter is a single-node
  fixed-window; it does not coordinate across replicas.
