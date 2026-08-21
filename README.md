# pccs-rs

Production **Rust + Tokio** replacement for [Intel PCCS](https://github.com/intel/confidential-computing.tee.dcap.pccs)
(Provisioning Certificate Caching Service). Intended to sit behind Caddy as
`pccs.phala.network`.

HTTP API is 1:1 with Intel Node PCCS. The cache is **RocksDB** (survives restart).
A cache-hit GET is one RocksDB get: the value is the response body plus Intel headers.

## How Phala would run it (Caddy)

Caddy terminates TLS. pccs-rs listens on HTTP:

```bash
pccs-rs \
  --http \
  --host 127.0.0.1 \
  --port 8081 \
  --db-path /var/lib/pccs/rocksdb \
  --uri https://pccs.phala.network/sgx/certification/v4/ \
  --cache-mode lazy \
  --user-token-hash <sha512-hex> \
  --admin-token-hash <sha512-hex>
```

Or a JSON config file (`--config /etc/pccs/config.json`) using the same field
names as Intel `service/config/default.json`, plus `DB_PATH` instead of sqlite:

```json
{
  "HTTPS_PORT": 8081,
  "hosts": "127.0.0.1",
  "uri": "https://pccs.phala.network/sgx/certification/v4/",
  "ApiKey": "",
  "proxy": "",
  "RefreshSchedule": "0 0 1 * * *",
  "UserTokenHash": "",
  "AdminTokenHash": "",
  "CachingFillMode": "LAZY",
  "LogLevel": "info",
  "DB_PATH": "/var/lib/pccs/rocksdb",
  "MaxRequestBodySize": "2MB",
  "RocksDbBlockCacheMb": 8,
  "RocksDbWriteBufferMb": 64,
  "RocksDbMaxWriteBuffers": 2,
  "RocksDbMaxOpenFiles": -1
}
```

- Default-dev upstream is Phala PCCS. **No Intel API key** is sent unless `uri`
  is Intel PCS (`api.trustedservices.intel.com`).
- `--https --cert certs/file.crt --key certs/private.pem` is also supported.
- `RefreshSchedule` is a 6-field cron (seconds first). Default: daily 01:00.

CLI overrides the file. Tokens are SHA-512 hex of the raw `user-token` /
`admin-token` header (timing-safe compare).

| Header         | Default raw token | Used for |
|----------------|-------------------|----------|
| `user-token`   | `user`            | `POST /platforms` |
| `admin-token`  | `admin`           | `GET /platforms`, `PUT /platformcollateral`, `GET\|POST /refresh`, `PUT /appraisalpolicy` |

## Caching modes

| Mode | GET miss | POST /platforms | Refresh |
|------|----------|-----------------|---------|
| **LAZY** | Fetch upstream, store, return. v3 miss → 410, no v3 call. | Fill from upstream if unknown | Allowed (cron + admin) |
| **REQ** | `/pckcert` → 461 if platform unknown; other GETs → 404. No upstream. | Register, fill, drain | Allowed |
| **OFFLINE** | Same as REQ (461 / 404). Never calls upstream. | Queue only | 503 |

Upstream is Intel PCS **or** another PCCS. Same paths (`pckcert`, `pckcrl`,
`tcb`, `qe/identity`, `qve/identity`, `rootcacrl`, `crl`). Intel uses
`pckcerts` + in-memory PCK selection; a PCCS upstream is a single GET.

## RocksDB key layout

`{type-prefix}{cityhash128(canonical fields) hex}` — keys lowercase. Values JSON.

| Prefix | Canonical fields | Value |
|--------|------------------|--------|
| `pckcert/` | qeid / pceid / cpusvn / pcesvn | PEM + SGX-TCBm, FMSPC, CA, issuer chain |
| `tcb/` | sgx\|tdx / version / fmspc / update | TCB JSON + issuer chain |
| `identity/` | qe\|qve\|tdqe / version / update | identity JSON + issuer chain |
| `pckcrl/` | ca | CRL bytes + issuer chain |
| `rootcacrl` | (literal) | CRL bytes |
| `crl/` | uri | CRL bytes |
| `appraisal/` | fmspc | policy list (GET joins defaults) |
| `preg/` | qeid / pceid / cpusvn / pcesvn | registration queue (GET /platforms?source=reg drain) |

Writes that Intel wrapped in a SQL transaction use a RocksDB `WriteBatch`.
zstd block compression. No Intel multi-table joins.

## What is implemented

- All 30 default v4 routes (SGX v3 + v4 + TDX v4)
- Auth, Request-ID, v3 Warning, Intel headers, plain-text errors, body limit
- LAZY / REQ / OFFLINE, real upstream client, cron refresh
- POST /platforms, GET /platforms (`reg` / `reg_na` / `[fmspc,…]`)
- PUT /platformcollateral → GET-shaped records
- GET/POST /refresh (collateral; `type=certs` re-fetches cached pckcerts)
- PUT/GET appraisalpolicy (SHA-384 id)
- PCK cert selection in memory when filling from Intel `pckcerts`

## How to bench

```bash
./scripts/bench.sh
# or:
cargo build --release --bin pccs-rs --bin loadgen
./target/release/pccs-rs --http --port 18081 --db-path /tmp/pccs-bench --uri '' --seed fixtures/seed.json &
./target/release/loadgen --url http://127.0.0.1:18081 --duration 5 --concurrency 32
```

Results: `bench-results.txt`. Mix is 70% `/pckcert` / 20% `/tcb` / 10% `/qe/identity`
against seeded v4 data (cache-hit, no Intel network).

```bash
cargo test
cargo build --release
```

## Memory

RocksDB RSS measured **27.1 MiB** on a 5s HTTP cache-hit bench (32 conc,
135k rps) with the shipped defaults (8 / 64 / 2 / -1). Higher than the old
in-memory DashMap (~8 MiB), far below Node PCCS (~112 MiB). See
`bench-results.txt` and `rocksdb-tune-results.md`.

### RocksDB memory flags

All four knobs are runtime-configurable (CLI overrides JSON / env). Applied
in `Store::open` via `Options` + `BlockBasedOptions` (zstd stays on).

| CLI | env | JSON | default |
|-----|-----|------|---------|
| `--rocksdb-block-cache-mb` | `PCCS_ROCKSDB_BLOCK_CACHE_MB` | `RocksDbBlockCacheMb` | 8 (stock LRU) |
| `--rocksdb-write-buffer-mb` | `PCCS_ROCKSDB_WRITE_BUFFER_MB` | `RocksDbWriteBufferMb` | 64 |
| `--rocksdb-max-write-buffers` | | `RocksDbMaxWriteBuffers` | 2 |
| `--rocksdb-max-open-files` | | `RocksDbMaxOpenFiles` | -1 (unlimited) |

```bash
pccs-rs --http --port 8081 \
  --rocksdb-block-cache-mb 8 \
  --rocksdb-write-buffer-mb 16 \
  --rocksdb-max-write-buffers 2 \
  --rocksdb-max-open-files -1
```

## API map

Mounted at `/sgx/certification/v3`, `/sgx/certification/v4`, and (v4) `/tdx/certification/v4`.

See `/workspace/pccs-api-inventory.md` for the full 1:1 contract (paths, headers,
status text). Collateral GETs are unauthenticated. `x-powered-by` is not set.
