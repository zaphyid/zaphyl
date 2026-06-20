# Reverse-proxy benchmark

A small, reproducible benchmark comparing Zaphyl against **nginx** and **Caddy**
as reverse proxies, all forwarding to one shared backend.

## What it measures

Each proxy forwards plaintext HTTP/1.1 (keep-alive, pooled upstream connections)
to the same backend, which returns a small fixed body. The load generator
([`oha`](https://github.com/hatoo/oha)) drives a fixed number of connections for
a fixed time and reports requests/sec and latency percentiles.

Because the backend is trivial and shared, the differences reflect **proxy
overhead**, not backend speed.

## Honest caveats - read these before quoting any number

- **Relative, not absolute.** These run on one developer machine (here, WSL2 on
  Windows, 12 vCPUs) over loopback. The load generator, all three proxies, and
  the backend share the same CPUs, so they contend with each other. Absolute
  requests/sec are **not** production figures and will differ on real hardware
  and real networks.
- **Same box, same instant.** The value is the side-by-side comparison under
  identical conditions, not the headline throughput.
- **HTTP/1.1 only.** This compares the common denominator all three speak
  identically. It does **not** exercise Zaphyl's HTTP/2, HTTP/3, TLS, caching, or
  plugin paths.
- **Default-ish configs.** Each proxy uses a small, comparable config (upstream
  keep-alive on for all three). These are not the vendors' maximally-tuned
  setups.
- **Micro-benchmark.** A fixed tiny response is the easiest case for every proxy.
  Real workloads (large bodies, TLS, slow clients, diverse routes) stress
  different code paths.

Treat the result as "is Zaphyl in the same ballpark as mature proxies for basic
forwarding?" - not as a leaderboard.

## Running it

Needs `nginx`, `caddy`, and `oha` available (no root required - the nginx
instances run unprivileged with configs under `/tmp/zaphyl-bench`), plus a
release build of Zaphyl:

```sh
cargo build --release --bin zaphyl
cd benchmarks
ZAPHYL=../target/release/zaphyl ./run.sh
```

Override `DURATION`, `ROUNDS`, or `CONNS` via environment variables. Ports used:
backend `18080`, Zaphyl `18081`, Caddy `18082`, nginx `18083`.

## Results

Recorded on WSL2 (Windows 11), 12 vCPUs, loopback, `DURATION=10s ROUNDS=3`.
Your absolute numbers will differ - reproduce with `./run.sh`.

### Concurrency 20

| Proxy  | Requests/sec | p50 (ms) | p99 (ms) |
|--------|-------------:|---------:|---------:|
| nginx  |      147,395 |     0.12 |     0.37 |
| zaphyl |       78,805 |     0.22 |     0.88 |
| caddy  |       50,516 |     0.33 |     1.23 |

### Concurrency 100

| Proxy  | Requests/sec | p50 (ms) | p99 (ms) |
|--------|-------------:|---------:|---------:|
| nginx  |      275,730 |     0.31 |     1.13 |
| zaphyl |      125,778 |     0.74 |     1.77 |
| caddy  |       69,517 |     0.76 |     6.71 |

### Honest read

- Zaphyl forwards faster than Caddy here and has a lower p99, but **nginx is
  about 2× faster** - unsurprising, since a tiny fixed response over loopback is
  exactly nginx's most-optimised case.
- This benchmark **caught a real bug**: Zaphyl originally ran on a single worker
  thread (Pingora's per-service default), so it was stuck near 21k req/s and
  didn't scale with concurrency. Defaulting the worker count to the number of
  CPUs (configurable via `worker_threads`) moved it to the numbers above.
- Closing the remaining gap to nginx is future tuning work, not a default-config
  problem.
