# pccs-rs

Production **Rust + Tokio** replacement for
[Intel PCCS](https://github.com/intel/confidential-computing.tee.dcap.pccs)
(Provisioning Certificate Caching Service). Intended to sit behind Caddy as
`pccs.phala.network`.

- HTTP API is 1:1 with Intel Node PCCS (all 30 default v4 routes: SGX v3 + v4,
  TDX v4).
- The cache is **RocksDB** and survives restart. A cache-hit GET is one RocksDB
  get: the value is the response body plus Intel headers.
- Licensed under [Apache 2.0](#license).

## Debian / Ubuntu package

Release artifacts include `pccs-rs_<version>_amd64.deb`, built against glibc
2.31 (Debian 11+, Ubuntu 20.04+). The package ships the binary, a systemd
unit, and `/etc/pccs-rs/config.toml`. Put Caddy or nginx in front if you want
TLS; this package does not include a reverse-proxy configuration.

```bash
sudo dpkg -i pccs-rs_<version>_amd64.deb
# set api_key in /etc/pccs-rs/config.toml, then:
sudo systemctl enable --now pccs-rs
```

To copy values out of an existing Node PCCS `pccs.json` / `default.json`:

```bash
sudo pccs-rs config import /opt/intel/sgx-dcap-pccs/config/default.json
```

That writes `/etc/pccs-rs/config.toml` (override with `--to`). An existing
destination is updated in place: keys present in the JSON are overwritten,
other keys and comments are kept.

## Running behind Caddy or nginx

Terminate TLS on the reverse proxy. pccs-rs listens on HTTP:

```bash
pccs-rs serve \
  --http \
  --host 127.0.0.1 \
  --port 8081 \
  --db-path /var/lib/pccs-rs \
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

Direct TLS is also supported: `pccs-rs serve --https --cert certs/file.crt --key certs/private.pem`.

## Configuration

The server starts with `pccs-rs serve`. CLI overrides the TOML config file,
which overrides built-in defaults. `serve` loads `--config` / `PCCS_CONFIG` if
set, otherwise `/etc/pccs-rs/config.toml` when that file exists. A named or
auto-selected file that is unreadable or invalid TOML is a fatal error, not a
silent fall-back to defaults.

The packaged file only needs `api_key` filled in. Everything else is optional:

```toml
api_key = ""
db_path = "/var/lib/pccs-rs"

# host = "127.0.0.1"
# port = 8081
# https = false
# cert = "certs/file.crt"
# key = "certs/private.pem"
# cache_mode = "lazy" # lazy | offline | req
# uri = "https://api.trustedservices.intel.com/sgx/certification/v4/"
# proxy is not supported; a non-empty value refuses to start.
# refresh_schedule = "0 0 1 * * *"
# user_token_hash = ""
# admin_token_hash = ""
# log_level = "info"
# max_request_body_size = "2MB"
# request_timeout_seconds = 15
# headers_timeout_seconds = 10
# keepalive_timeout_seconds = 60
# upstream_max_concurrent = 64
# upstream_max_attempts = 6
# upstream_pool_idle_seconds = 60
# rocksdb_block_cache_mb = 8
# rocksdb_write_buffer_mb = 64
# rocksdb_max_write_buffers = 2
# rocksdb_max_open_files = -1
```

Notes:

- Default upstream is Intel PCS, the same as Node `config/default.json`.
- `api_key` (`Ocp-Apim-Subscription-Key`) is sent exactly where Node sends it:
  on `pckcerts` requests, and on every request to the early-access portal
  (`https://validation.api.trustedservices.intel.com/`). Never on CRL downloads.
- `proxy` is **not supported**; startup fails if it is set. Remove it and run
  pccs-rs on a host with direct outbound access.
- `refresh_schedule` is a 6-field cron (seconds first). Default: daily 01:00.
- SIGINT / SIGTERM shuts down gracefully (10s for in-flight requests) and
  closes RocksDB.

### Tokens

**There is no default token.** `user_token_hash` / `admin_token_hash` are empty out
of the box; an empty or malformed hash logs an ERROR at startup and every
request to an endpoint guarded by that token answers `401`. Tokens are SHA-512
hex of the raw header value (timing-safe compare):

```bash
printf '%s' '<token>' | shasum -a 512
```

| Header        | Guards |
|---------------|--------|
| `user-token`  | `POST /platforms` |
| `admin-token` | `GET /platforms`, `PUT /platformcollateral`, `GET\|POST /refresh`, `PUT /appraisalpolicy` |

Collateral GETs are unauthenticated. For local development and benchmarking,
`--dev-tokens` enables built-in hashes for the raw tokens `user` / `admin` and
logs a loud warning. Never in production.

### Timeouts and upstream limits

| CLI | env | TOML | default |
|-----|-----|------|---------|
| `--request-timeout-seconds` | `PCCS_REQUEST_TIMEOUT_SECONDS` | `request_timeout_seconds` | 15 |
| `--headers-timeout-seconds` | `PCCS_HEADERS_TIMEOUT_SECONDS` | `headers_timeout_seconds` | 10 |
| `--keepalive-timeout-seconds` | `PCCS_KEEPALIVE_TIMEOUT_SECONDS` | `keepalive_timeout_seconds` | 60 |
| `--upstream-max-concurrent` | `PCCS_UPSTREAM_MAX_CONCURRENT` | `upstream_max_concurrent` | 64 |
| `--upstream-max-attempts` | `PCCS_UPSTREAM_MAX_ATTEMPTS` | `upstream_max_attempts` | 6 |
| `--upstream-pool-idle-seconds` | `PCCS_UPSTREAM_POOL_IDLE_SECONDS` | `upstream_pool_idle_seconds` | 60 |

`RequestTimeoutSeconds` bounds **receiving** a request, matching Node's
`server.requestTimeout` — the headers half via hyper's header read timeout, the
body half via a timeout around body collection (a client that stalls mid-body
gets `408`). It deliberately does **not** cancel the handler: a LAZY miss may
legitimately wait on a 120s upstream budget, and an admin `/refresh` walks the
whole cache. Cancelling those mid-write is how a half-written platform record
happens, so response production is left unbounded, exactly as in Node.

Upstream requests: 120s total timeout, 10s connect timeout, 16 MiB response
cap, at most `UpstreamMaxConcurrent` in flight, `UpstreamMaxAttempts` tries
(429/503 retried at most twice, honouring `Retry-After`).
`UpstreamMaxAttempts` mirrors Node `pcs_client.js` `MAX_RETRY_COUNT`.

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
the registration queue with state `1`, readable via
`GET /platforms?source=reg_na` (Node `processNotAvailableTcbs`).

### Upstream: Intel PCS or another PCCS

Same paths (`pckcert`, `pckcrl`, `tcb`, `qe/identity`, `qve/identity`,
`rootcacrl`, `crl`). Intel uses `pckcerts` + in-memory PCK selection; a PCCS
upstream is a single GET.

Intel PCS has no `rootcacrl` route. Like Node, the root CA CRL URL is taken
from the CRL Distribution Point of the Intel root CA certificate (the last PEM
of an issuer chain); if that cannot be read, pccs-rs falls back to
`https://certificates.trustedservices.intel.com/IntelSGXRootCA.der` and logs
it. A PCCS upstream keeps serving `{base}rootcacrl`.

## Connection reuse

`KeepAliveTimeoutSeconds` is how long an idle client connection is held open
between requests — this is the value a reverse proxy in front of pccs-rs cares
about, and it must be at least as long as the proxy's own idle timeout (Caddy
defaults to 90s; raise `KeepAliveTimeoutSeconds` to match if you see the proxy
reconnect on every request). `HeadersTimeoutSeconds` is separate: it bounds
only a *freshly accepted* connection, which must send the first byte of a
request within that window or be dropped. A partial request head that stalls on
an already established keep-alive connection is bounded by
`KeepAliveTimeoutSeconds` instead. On the HTTPS path `HeadersTimeoutSeconds`
bounds the TLS handshake.

Accepted sockets get `TCP_NODELAY` and 60s `SO_KEEPALIVE` probes. Upstream
sockets get the same, plus a connection pool: up to `UpstreamMaxConcurrent`
idle connections per host, dropped after `UpstreamPoolIdleSeconds` (default 60,
deliberately under the idle timeout of Intel PCS and of a PCCS behind a proxy,
so a pooled connection is never handed a request after the far end closed it).
Set it to 0 to disable pooling.

## RocksDB key layout

`{type-prefix}{cityhash128(canonical fields) hex}` — keys lowercase. Values
JSON.

| Prefix | Canonical fields | Value |
|--------|------------------|-------|
| `platform/` | qeid / pceid | the platform's **whole PCK cert pool** + fmspc, ca, enc_ppid, platform_manifest, issuer chain, and its known raw TCB levels |
| `pckcert/` | qeid / pceid / cpusvn / pcesvn | selected PEM + SGX-TCBm, FMSPC, CA, issuer chain (hot path) |
| `tcb/` | sgx\|tdx / version / fmspc / update | TCB JSON + issuer chain |
| `identity/` | qe\|qve\|tdqe / version / update | identity JSON + issuer chain |
| `pckcrl/` | ca | CRL bytes + issuer chain |
| `rootcacrl` | (literal) | CRL bytes |
| `crl/` | uri | CRL bytes |
| `appraisal/` | fmspc | policy list (GET joins defaults) |
| `preg/` | qeid / pceid / cpusvn / pcesvn | registration queue (`GET /platforms?source=reg` drain) |

`platform/` collapses Intel's `platforms`, `pck_cert` and `platform_tcbs`
tables into one record, so `GET /pckcert` for a platform that is known but
whose raw TCB has never been seen is answered by running PCK cert selection
locally instead of calling upstream, and `has_platform` is a single `DB::get`
rather than a full scan.

Every read re-checks the stored record against the key it was fetched with
(qeid / pceid / cpusvn / pcesvn, fmspc, update type …); a mismatch counts as a
miss instead of serving another platform's collateral.

Writes that Intel wrapped in a SQL transaction use a RocksDB `WriteBatch`.
zstd block compression. No Intel multi-table joins.

### Migration from pre-`platform/` databases

Databases written before `platform/` existed have `pckcert/` records but no
platform records. Nothing needs to be deleted and nothing is lost, but two
behaviours change until the platform records are refilled:

- **`GET /platforms?source=[fmspc]` comes back empty.** The listing now
  iterates `platform/` records rather than scanning `pckcert/`, and a
  pre-existing DB has none. It refills as platforms are re-registered
  (`POST /platforms`), re-seeded, supplied via `PUT /platformcollateral`, or —
  in LAZY mode — fetched upstream on the first request for them.
- **Those platforms read as unknown**, so REQ / OFFLINE answer `461`. LAZY
  refills from the upstream on the first request.

Old `pckcert/` records keep working throughout: an exact-key hit (same qeid /
pceid / cpusvn / pcesvn) is still served straight from cache.

## What is implemented

- All 30 default v4 routes (SGX v3 + v4 + TDX v4), mounted at
  `/sgx/certification/v3`, `/sgx/certification/v4`, and `/tdx/certification/v4`
- Auth, Request-ID (always freshly generated, like Node), v3 Warning, Intel
  headers, `text/html` error bodies, body limit (413 `Content too large.`),
  `x-powered-by` not set
- LAZY / REQ / OFFLINE, real upstream client, cron refresh
- `POST /platforms` (body must be a JSON **object**, per Node's
  `PLATFORM_REG_SCHEMA`; arrays are `400`), `GET /platforms`
  (`reg` / `reg_na` / `[fmspc,…]` — the fmspc listing returns exactly `qe_id`,
  `pce_id`, `cpu_svn`, `pce_svn`, `enc_ppid`, `platform_manifest`)
- `PUT /platformcollateral`, validated against Intel's
  `PLATFORM_COLLATERAL_SCHEMA_V3` / `_V4` before anything is stored
- `GET|POST /refresh` (collateral; `type=certs` re-fetches each platform's pool)
- `PUT|GET /appraisalpolicy` (SHA-384 id, upsert by id, one default per fmspc,
  JWS payload and `class_id` validated as Node does)
- Full PCK cert selection (`pckCertSelection.js` + `Tcb.js` + the SGX X.509
  extension reader from `x509.js`): a certificate's TCB is read from the
  certificate, never from `tcbm`, PCESVN is a full integer, and an unparsable
  certificate is an error rather than a fallback
- Platform registration by `platform_manifest` (`POST {base}pckcerts`)
- Duplicated query parameters take the first value
  (`filterDuplicatedParams.js`); signed TCB-info / enclave-identity bodies are
  stored and returned byte-for-byte, so their signatures still verify

## Benchmarks

```bash
./scripts/bench.sh
# or manually:
cargo build --release --bin pccs-rs --bin loadgen
./target/release/pccs-rs serve --http --port 18081 --db-path /tmp/pccs-bench --uri '' --seed fixtures/seed.json &
./target/release/loadgen --url http://127.0.0.1:18081 --duration 5 --concurrency 32
```

Local dumps go to `compare/out/` (gitignored). Mix is 70% `/pckcert` /
20% `/tcb` / 10% `/qe/identity` against seeded v4 data (cache-hit, no Intel
network).

RocksDB RSS measured **27.1 MiB** on a 5s HTTP cache-hit bench (32 conc,
135k rps) with the shipped defaults (8 / 64 / 2 / -1). Higher than the old
in-memory DashMap (~8 MiB), far below Node PCCS (~112 MiB). Node vs Rust
compare summary: [`docs/compare-results.md`](docs/compare-results.md).

### RocksDB memory flags

All four knobs are runtime-configurable (CLI overrides TOML / env). Applied in
`Store::open` via `Options` + `BlockBasedOptions` (zstd stays on).

| CLI | env | TOML | default |
|-----|-----|------|---------|
| `--rocksdb-block-cache-mb` | `PCCS_ROCKSDB_BLOCK_CACHE_MB` | `rocksdb_block_cache_mb` | 8 (stock LRU) |
| `--rocksdb-write-buffer-mb` | `PCCS_ROCKSDB_WRITE_BUFFER_MB` | `rocksdb_write_buffer_mb` | 64 |
| `--rocksdb-max-write-buffers` | | `rocksdb_max_write_buffers` | 2 |
| `--rocksdb-max-open-files` | | `rocksdb_max_open_files` | -1 (unlimited) |

```bash
pccs-rs serve --http --port 8081 \
  --rocksdb-block-cache-mb 8 \
  --rocksdb-write-buffer-mb 16 \
  --rocksdb-max-write-buffers 2 \
  --rocksdb-max-open-files -1
```

## Development

```bash
cargo test
cargo build --release
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
