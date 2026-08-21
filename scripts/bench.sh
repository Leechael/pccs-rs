#!/usr/bin/env bash
# Simulated cache-hit benchmark (HTTP, no TLS, no Intel PCS).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-18081}"
DURATION="${DURATION:-5}"
CONCURRENCY="${CONCURRENCY:-32}"
OUT="${OUT:-$ROOT/bench-results.txt}"
DB="${DB:-/tmp/pccs-rs-bench-db}"

echo "==> building release binaries"
cargo build --release --bin pccs-rs --bin loadgen

BIN="$ROOT/target/release/pccs-rs"
LOAD="$ROOT/target/release/loadgen"

rm -rf "$DB"
echo "==> starting pccs-rs on :$PORT (RocksDB $DB)"
"$BIN" --http --port "$PORT" --host 127.0.0.1 --cache-mode lazy --db-path "$DB" --uri "" --seed "$ROOT/fixtures/seed.json" &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }
trap cleanup EXIT

ready=0
for _ in $(seq 1 80); do
  if curl -sf "http://127.0.0.1:${PORT}/sgx/certification/v4/pckcert?qeid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&cpusvn=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&pcesvn=CCCC&pceid=DDDD" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" != 1 ]]; then
  echo "server failed to become ready on :$PORT" >&2
  exit 1
fi

echo "==> running loadgen (${CONCURRENCY} conc, ${DURATION}s)"
"$LOAD" --url "http://127.0.0.1:${PORT}" --duration "$DURATION" --concurrency "$CONCURRENCY" | tee "$OUT"
RSS_KB=$(awk '/^VmRSS:/ {print $2}' /proc/$PID/status 2>/dev/null || echo 0)
RSS_MIB=$(awk -v k="$RSS_KB" 'BEGIN{printf "%.1f", k/1024}')
{
  echo "measured: $(TZ=Asia/Taipei date '+%Y-%m-%d %H:%M %Z') (UTC+8)"
  echo "rocksdb_rss_mib: $RSS_MIB"
} >> "$OUT"
echo "==> wrote $OUT (VmRSS ${RSS_MIB} MiB)"
