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
  --uri https://api.trustedservices.intel.com/sgx/certification/v4/ \
  --api-key <intel-subscription-key> \
  --cache-mode lazy \
  --user-token-hash <sha512-hex> \
  --admin-token-hash <sha512-hex>
```

`--uri` is the **upstream** this cache fills from — Intel PCS, or another PCCS.
It must never be this service's own public hostname (e.g. `pccs.phala.network`
when that name resolves back here): every cache miss would then call back into
pccs-rs and recurse. Startup logs a warning when the `uri` host looks like the
address we bind.

Or a JSON config file (`--config /etc/pccs/config.json`) using the same field
names as Intel `service/config/default.json`, plus `DB_PATH` instead of sqlite:

```json
{
  "HTTPS_PORT": 8081,
  "hosts": "127.0.0.1",
  "uri": "https://api.trustedservices.intel.com/sgx/certification/v4/",
  "ApiKey": "",
  "proxy": "",
  "RefreshSchedule": "0 0 1 * * *",
  "UserTokenHash": "",
  "AdminTokenHash": "",
  "CachingFillMode": "LAZY",
  "LogLevel": "info",
  "DB_PATH": "/var/lib/pccs/rocksdb",
  "MaxRequestBodySize": "2MB",
  "RequestTimeoutSeconds": 15,
  "HeadersTimeoutSeconds": 10,
  "KeepAliveTimeoutSeconds": 60,
  "UpstreamMaxConcurrent": 64,
  "UpstreamMaxAttempts": 6,
  "RocksDbBlockCacheMb": 8,
  "RocksDbWriteBufferMb": 64,
  "RocksDbMaxWriteBuffers": 2,
  "RocksDbMaxOpenFiles": -1
}
```

- Default upstream is Intel PCS, the same as Node `config/default.json`.
- `ApiKey` (`Ocp-Apim-Subscription-Key`) is sent exactly where Node sends it:
  on `pckcerts` requests, and on every request to the early-access portal
  (`https://validation.api.trustedservices.intel.com/`). Never on CRL downloads.
- `proxy` is **not supported**; startup fails if it is set. Remove it and run
  pccs-rs on a host with direct outbound access.
- A named `--config` file that is unreadable or not valid JSON is a fatal error,
  not a silent fall-back to the built-in defaults.
- `--https --cert certs/file.crt --key certs/private.pem` is also supported.
- `RefreshSchedule` is a 6-field cron (seconds first). Default: daily 01:00.
- `RequestTimeoutSeconds` / `HeadersTimeoutSeconds` / `KeepAliveTimeoutSeconds`
  mirror the Node HTTP server timeouts. SIGINT / SIGTERM shuts down gracefully
  (10s for in-flight requests) and closes RocksDB.
- Upstream requests: 120s total timeout, 10s connect timeout, 16 MiB response
  cap, at most `UpstreamMaxConcurrent` in flight, `UpstreamMaxAttempts` tries
  (429/503 retried at most twice, honouring `Retry-After`).

CLI overrides the file. Tokens are SHA-512 hex of the raw `user-token` /
`admin-token` header (timing-safe compare).

**There is no default token.** `UserTokenHash` / `AdminTokenHash` are empty out
of the box; an empty or malformed hash logs an ERROR at startup and makes every
request to the endpoints guarded by that token answer `401`. Generate one with
`printf '%s' '<token>' | shasum -a 512`.

| Header         | Used for |
|----------------|----------|
| `user-token`   | `POST /platforms` |
| `admin-token`  | `GET /platforms`, `PUT /platformcollateral`, `GET\|POST /refresh`, `PUT /appraisalpolicy` |

For local development and benchmarking, `--dev-tokens` enables built-in hashes
for the raw tokens `user` / `admin` and logs a loud warning. Never in production.

## Caching modes

| Mode | GET miss | POST /platforms | Refresh |
|------|----------|-----------------|---------|
| **LAZY** | Fetch upstream, store, return. v3 miss → 410, no v3 call. | Fill from upstream if unknown; a failed fill fails the POST | Allowed (cron + admin) |
| **REQ** | `/pckcert` → 461 if platform unknown; other GETs → 404. No upstream. | Queue, fill, then drop **only this platform's** queue row; a failed fill keeps the row and fails the POST | Allowed |
| **OFFLINE** | Same as REQ (461 / 404). Never calls upstream. | Queue only | 503 (after parameter validation) |

In every mode a `/pckcert` miss for a *known* platform first runs PCK cert
selection against the cached pool; only if that fails does LAZY go upstream and
REQ / OFFLINE answer 404. Concurrent misses on the same key are de-duplicated:
50 simultaneous requests produce one upstream fetch. `GET|POST /refresh` is
serialised, and a CRL or TCB-info refresh that the upstream cannot satisfy is a
`503` rather than a silent success.

In REQ mode, TCB levels that Intel reports as `"Not available"` are written to
the registration queue with state `1`, readable via `GET /platforms?source=reg_na`
(Node `processNotAvailableTcbs`).

Upstream is Intel PCS **or** another PCCS. Same paths (`pckcert`, `pckcrl`,
`tcb`, `qe/identity`, `qve/identity`, `rootcacrl`, `crl`). Intel uses
`pckcerts` + in-memory PCK selection; a PCCS upstream is a single GET.

Intel PCS has no `rootcacrl` route. Like Node, the root CA CRL URL is taken from
the CRL Distribution Point of the Intel root CA certificate (the last PEM of an
issuer chain); if that cannot be read, pccs-rs falls back to
`https://certificates.trustedservices.intel.com/IntelSGXRootCA.der` and logs it.
A PCCS upstream keeps serving `{base}rootcacrl`.

## Timeouts and upstream limits

CLI overrides JSON config, which overrides the built-in default.

| CLI | env | JSON | default |
|-----|-----|------|---------|
| `--request-timeout-seconds` | `PCCS_REQUEST_TIMEOUT_SECONDS` | `RequestTimeoutSeconds` | 15 |
| `--headers-timeout-seconds` | `PCCS_HEADERS_TIMEOUT_SECONDS` | `HeadersTimeoutSeconds` | 10 |
| `--keepalive-timeout-seconds` | `PCCS_KEEPALIVE_TIMEOUT_SECONDS` | `KeepAliveTimeoutSeconds` | 60 |
| `--upstream-max-concurrent` | `PCCS_UPSTREAM_MAX_CONCURRENT` | `UpstreamMaxConcurrent` | 64 |
| `--upstream-max-attempts` | `PCCS_UPSTREAM_MAX_ATTEMPTS` | `UpstreamMaxAttempts` | 6 |

`RequestTimeoutSeconds` bounds **receiving** a request, matching Node's
`server.requestTimeout` — the headers half via hyper's header read timeout, the
body half via a timeout around body collection (a client that stalls mid-body
gets `408`). It deliberately does **not** cancel the handler: a LAZY miss may
legitimately wait on a 120s upstream budget, and an admin `/refresh` walks the
whole cache. Cancelling those mid-write is how a half-written platform record
happens, so response production is left unbounded, exactly as in Node.

`UpstreamMaxAttempts` mirrors Node `pcs_client.js` `MAX_RETRY_COUNT`.

## RocksDB key layout

`{type-prefix}{cityhash128(canonical fields) hex}` — keys lowercase. Values JSON.

| Prefix | Canonical fields | Value |
|--------|------------------|--------|
| `platform/` | qeid / pceid | the platform's **whole PCK cert pool** + fmspc, ca, enc_ppid, platform_manifest, issuer chain, and its known raw TCB levels |
| `pckcert/` | qeid / pceid / cpusvn / pcesvn | selected PEM + SGX-TCBm, FMSPC, CA, issuer chain (hot path) |
| `tcb/` | sgx\|tdx / version / fmspc / update | TCB JSON + issuer chain |
| `identity/` | qe\|qve\|tdqe / version / update | identity JSON + issuer chain |
| `pckcrl/` | ca | CRL bytes + issuer chain |
| `rootcacrl` | (literal) | CRL bytes |
| `crl/` | uri | CRL bytes |
| `appraisal/` | fmspc | policy list (GET joins defaults) |
| `preg/` | qeid / pceid / cpusvn / pcesvn | registration queue (GET /platforms?source=reg drain) |

`platform/` collapses Intel's `platforms`, `pck_cert` and `platform_tcbs`
tables into one record, so `GET /pckcert` for a platform that is known but whose
raw TCB has never been seen is answered by running PCK cert selection locally
instead of calling upstream, and `has_platform` is a single `DB::get` rather
than a full scan.

Every read re-checks the stored record against the key it was fetched with
(qeid / pceid / cpusvn / pcesvn, fmspc, update type …); a mismatch counts as a
miss instead of serving another platform's collateral.

**Migration.** Databases written before `platform/` existed have `pckcert/`
records but no platform records. Nothing needs to be deleted and nothing is
lost, but two behaviours change until the platform records are refilled:

- **`GET /platforms?source=[fmspc]` comes back empty.** The listing now
  iterates `platform/` records rather than scanning `pckcert/`, and a
  pre-existing DB has none. It refills as platforms are re-registered
  (`POST /platforms`), re-seeded, supplied via `PUT /platformcollateral`, or —
  in LAZY mode — fetched upstream on the first request for them.
- **Those platforms read as unknown**, so REQ / OFFLINE answer `461`. LAZY
  refills from the upstream on the first request.

Old `pckcert/` records keep working throughout: an exact-key hit
(same qeid / pceid / cpusvn / pcesvn) is still served straight from cache.

Writes that Intel wrapped in a SQL transaction use a RocksDB `WriteBatch`.
zstd block compression. No Intel multi-table joins.

## What is implemented

- All 30 default v4 routes (SGX v3 + v4 + TDX v4)
- Auth, Request-ID (always freshly generated, like Node), v3 Warning, Intel
  headers, `text/html` error bodies, body limit (413 `Content too large.`)
- LAZY / REQ / OFFLINE, real upstream client, cron refresh
- POST /platforms (body must be a JSON **object**, per Node's
  `PLATFORM_REG_SCHEMA`; arrays are `400`), GET /platforms
  (`reg` / `reg_na` / `[fmspc,…]` — the fmspc listing returns exactly
  `qe_id`, `pce_id`, `cpu_svn`, `pce_svn`, `enc_ppid`, `platform_manifest`)
- PUT /platformcollateral, validated against Intel's
  `PLATFORM_COLLATERAL_SCHEMA_V3` / `_V4` before anything is stored
- GET/POST /refresh (collateral; `type=certs` re-fetches each platform's pool)
- PUT/GET appraisalpolicy (SHA-384 id, upsert by id, one default per fmspc,
  JWS payload and `class_id` validated as Node does)
- Full PCK cert selection (`pckCertSelection.js` + `Tcb.js` + the SGX X.509
  extension reader from `x509.js`): a certificate's TCB is read from the
  certificate, never from `tcbm`, PCESVN is a full integer, and an unparsable
  certificate is an error rather than a fallback
- Platform registration by `platform_manifest` (`POST {base}pckcerts`)
- Duplicated query parameters take the first value
  (`filterDuplicatedParams.js`); signed TCB-info / enclave-identity bodies are
  stored and returned byte-for-byte, so their signatures still verify

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
