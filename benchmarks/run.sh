#!/usr/bin/env bash
#
# Reverse-proxy micro-benchmark: Zaphyl vs nginx vs Caddy, all forwarding to one
# shared backend over plaintext HTTP/1.1 with keep-alive. Reports requests/sec
# and latency percentiles as a markdown table.
#
# This measures *relative* proxy overhead on one machine. The absolute numbers
# are not production figures - see README.md for the (important) caveats.
#
# Requirements (no root needed): nginx, caddy, oha on PATH or pointed at via the
# env vars below, plus a release build of zaphyl.
#
#   ZAPHYL=../target/release/zaphyl NGINX=$(command -v nginx) \
#   CADDY=~/bin/caddy OHA=~/bin/oha ./run.sh
set -euo pipefail

cd "$(dirname "$0")"
HERE="$PWD"
WORK=/tmp/zaphyl-bench

ZAPHYL="${ZAPHYL:-$HERE/../target/release/zaphyl}"
NGINX="${NGINX:-$(command -v nginx || true)}"
CADDY="${CADDY:-$(command -v caddy || echo "$HOME/bin/caddy")}"
OHA="${OHA:-$(command -v oha || echo "$HOME/bin/oha")}"

DURATION="${DURATION:-8s}"
ROUNDS="${ROUNDS:-2}"
CONNS="${CONNS:-20 100}"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    [ -f "$WORK/backend/nginx.pid" ] && kill "$(cat "$WORK/backend/nginx.pid")" 2>/dev/null || true
    [ -f "$WORK/proxy-nginx/nginx.pid" ] && kill "$(cat "$WORK/proxy-nginx/nginx.pid")" 2>/dev/null || true
}
trap cleanup EXIT

for tool in "$ZAPHYL" "$NGINX" "$CADDY" "$OHA"; do
    [ -x "$tool" ] || { echo "missing or not executable: $tool" >&2; exit 1; }
done

rm -rf "$WORK"
mkdir -p "$WORK/backend" "$WORK/proxy-nginx"

# Free the bench ports in case a previous run left something behind.
for p in 18080 18081 18082 18083; do fuser -k "$p/tcp" 2>/dev/null || true; done
sleep 1

wait_port() {
    for _ in $(seq 1 100); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&-; return 0; }
        sleep 0.1
    done
    echo "port $1 ($2) never came up; last log lines:" >&2
    tail -5 "$WORK/$2".log "$WORK/$2"/error.log 2>/dev/null >&2 || true
    return 1
}

echo "Starting backend + proxies..."
"$NGINX" -c "$HERE/backend.nginx.conf" -p "$WORK/backend" &
PIDS+=($!); wait_port 18080 backend

"$ZAPHYL" --config "$HERE/zaphyl.toml" >"$WORK/zaphyl.log" 2>&1 &
PIDS+=($!); wait_port 18081 zaphyl

"$CADDY" run --config "$HERE/proxy.caddy.json" >"$WORK/caddy.log" 2>&1 &
PIDS+=($!); wait_port 18082 caddy

"$NGINX" -c "$HERE/proxy.nginx.conf" -p "$WORK/proxy-nginx" &
PIDS+=($!); wait_port 18083 proxy-nginx

# name:port for each target under test.
TARGETS=("zaphyl:18081" "nginx:18083" "caddy:18082")

# Parse oha -j JSON for requests/sec and p50/p99 (ms).
parse() {
    python3 -c '
import json,sys
d=json.load(sys.stdin)
rps=d["summary"]["requestsPerSec"]
p=d.get("latencyPercentiles",{})
p50=p.get("p50",0)*1000; p99=p.get("p99",0)*1000
print(f"{rps:.0f} {p50:.2f} {p99:.2f}")
'
}

declare -A RESULT
for conn in $CONNS; do
    for entry in "${TARGETS[@]}"; do
        name="${entry%%:*}"; port="${entry##*:}"
        url="http://127.0.0.1:$port/"
        "$OHA" -z 3s -c "$conn" --no-tui --output-format json "$url" >/dev/null 2>&1 || true
        best_rps=0; best_line="0 0 0"
        for _ in $(seq 1 "$ROUNDS"); do
            line=$("$OHA" -z "$DURATION" -c "$conn" --no-tui --output-format json "$url" | parse)
            rps=${line%% *}
            if [ "$rps" -gt "$best_rps" ]; then best_rps=$rps; best_line=$line; fi
        done
        RESULT["$name,$conn"]="$best_line"
        echo "  c=$conn $name: $best_line (rps p50ms p99ms)"
    done
done

echo
echo "## Results (requests/sec, higher is better)"
echo
for conn in $CONNS; do
    echo "### Concurrency $conn"
    echo
    echo "| Proxy | Requests/sec | p50 latency (ms) | p99 latency (ms) |"
    echo "|-------|-------------:|-----------------:|-----------------:|"
    for entry in "${TARGETS[@]}"; do
        name="${entry%%:*}"
        read -r rps p50 p99 <<<"${RESULT[$name,$conn]}"
        printf "| %s | %s | %s | %s |\n" "$name" "$rps" "$p50" "$p99"
    done
    echo
done
