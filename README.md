# pccs-rs

Rust + Tokio replacement for
[Intel PCCS](https://github.com/intel/confidential-computing.tee.dcap.pccs)
(Provisioning Certificate Caching Service). HTTP API is 1:1 with Node PCCS
(SGX v3 + v4, TDX v4) and also provides a read-through AMD KDS cache for `/vcek/` and `/vlek/`.
The cache is RocksDB and survives restart.

Sit it behind Caddy or nginx. This repo does not ship a reverse-proxy config.

## 5-minute kickoff

Intel collateral requires an Intel PCS API key (`Ocp-Apim-Subscription-Key`).
AMD KDS caching needs no API key. Everything else has a built-in default.

### Debian / Ubuntu

`.deb` is built against glibc 2.31 (Debian 11+, Ubuntu 20.04+).

```bash
sudo dpkg -i pccs-rs_<version>_amd64.deb
sudo $EDITOR /etc/pccs-rs/config.toml   # set api_key = "..."
sudo systemctl enable --now pccs-rs
```

Coming from Node PCCS? Import instead of editing by hand:

```bash
sudo pccs-rs config import /opt/intel/sgx-dcap-pccs/config/default.json
sudo systemctl enable --now pccs-rs
```

### From source

```bash
cargo build --release --bin pccs-rs
./target/release/pccs-rs serve --api-key <intel-subscription-key>
```

Listens on `127.0.0.1:8081`. Point Caddy or nginx at that address.

### Check it is up

```bash
curl -sS -D- -o /dev/null http://127.0.0.1:8081/sgx/certification/v4/rootcacrl
```

A live process answers with a `Request-ID` header. Collateral GETs are
unauthenticated; admin / registration routes need tokens (none are set by
default).

## Usage

```text
pccs-rs serve [OPTIONS]          start the HTTP server
pccs-rs config import <FILE>     convert a Node pccs.json into TOML
```

`serve` loads `--config` / `PCCS_CONFIG` if set, otherwise
`/etc/pccs-rs/config.toml` when that file exists. CLI flags override the file,
which overrides built-in defaults. A named or auto-selected file that cannot
be read or parsed is fatal.

Common flags (all have `PCCS_*` env equivalents):

```bash
pccs-rs serve \
  --config /etc/pccs-rs/config.toml \
  --host 127.0.0.1 \
  --port 8081 \
  --api-key <intel-subscription-key> \
  --db-path /var/lib/pccs-rs \
  --cache-mode lazy
```

`--uri` is the **upstream** this cache fills from — Intel PCS, or another
PCCS. It must never be this service's own public hostname: a cache miss would
call back into pccs-rs and recurse. Startup warns when the `uri` host looks
like the bind address.

Direct TLS: `pccs-rs serve --https --cert certs/file.crt --key certs/private.pem`.
Prefer terminating TLS on Caddy or nginx.

`config import` writes `/etc/pccs-rs/config.toml` by default (`--to` to
override). An existing destination is updated in place: keys present in the
JSON are overwritten, other keys and comments are kept.

## Configuration

The packaged file only needs `api_key`. Uncomment anything else to override.

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
# amd_kds_uri = "https://kdsintf.amd.com"
# amd_kds_cache_ttl_seconds = 2592000 # 30 days
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

- Default Intel upstream is Intel PCS. The AMD KDS host defaults to
  `https://kdsintf.amd.com`. Request paths under `/vcek/` and `/vlek/` are
  forwarded unchanged. A legacy `.../vcek/v1` or `.../vlek/v1` suffix on the
  configured host is stripped.
- AMD KDS responses are cached for 30 days by default. Only successful `200`
  responses are stored; the full upstream URL, including the TCB query string,
  is the cache key.
- `api_key` is sent where Node sends it: on `pckcerts`, and on every request
  to `https://validation.api.trustedservices.intel.com/`. Never on CRL
  downloads.
- `proxy` is not supported. Startup fails if it is set.
- `refresh_schedule` is a 6-field cron (seconds first). Default: daily 01:00.
- SIGINT / SIGTERM shuts down gracefully (10s for in-flight requests) and
  closes RocksDB.

### Tokens

There is no default token. Empty or malformed `user_token_hash` /
`admin_token_hash` logs an ERROR at startup and every guarded request answers
`401`. Tokens are SHA-512 hex of the raw header value:

```bash
printf '%s' '<token>' | shasum -a 512
```

| Header        | Guards |
|---------------|--------|
| `user-token`  | `POST /platforms` |
| `admin-token` | `GET /platforms`, `PUT /platformcollateral`, `GET\|POST /refresh`, `PUT /appraisalpolicy` |

Collateral GETs are unauthenticated. `--dev-tokens` enables built-in hashes
for the raw tokens `user` / `admin` and logs a warning. Never in production.

### Timeouts and upstream limits

| CLI | env | TOML | default |
|-----|-----|------|---------|
| `--request-timeout-seconds` | `PCCS_REQUEST_TIMEOUT_SECONDS` | `request_timeout_seconds` | 15 |
| `--headers-timeout-seconds` | `PCCS_HEADERS_TIMEOUT_SECONDS` | `headers_timeout_seconds` | 10 |
| `--keepalive-timeout-seconds` | `PCCS_KEEPALIVE_TIMEOUT_SECONDS` | `keepalive_timeout_seconds` | 60 |
| `--upstream-max-concurrent` | `PCCS_UPSTREAM_MAX_CONCURRENT` | `upstream_max_concurrent` | 64 |
| `--upstream-max-attempts` | `PCCS_UPSTREAM_MAX_ATTEMPTS` | `upstream_max_attempts` | 6 |
| `--upstream-pool-idle-seconds` | `PCCS_UPSTREAM_POOL_IDLE_SECONDS` | `upstream_pool_idle_seconds` | 60 |

`request_timeout_seconds` bounds **receiving** a request (headers + body),
matching Node's `server.requestTimeout`. It does not cancel the handler: a
LAZY miss may wait on a 120s upstream budget, and `/refresh` walks the whole
cache.

`keepalive_timeout_seconds` is how long an idle client connection is held
open. Keep it at least as long as the reverse proxy's idle timeout (Caddy
defaults to 90s). `headers_timeout_seconds` only bounds a freshly accepted
connection.

Upstream requests: 120s total, 10s connect, 16 MiB response cap,
`upstream_max_attempts` tries (429/503 retried at most twice, honouring
`Retry-After`).

### Caching modes

| Mode | GET miss | POST /platforms | Refresh |
|------|----------|-----------------|---------|
| **LAZY** | Fetch upstream, store, return. v3 miss → 410. | Fill if unknown; a failed fill fails the POST | Allowed |
| **REQ** | `/pckcert` → 461 if unknown; other GETs → 404 | Queue, fill, drop this platform's row | Allowed |
| **OFFLINE** | Same as REQ. Never calls upstream. | Queue only | 503 |

A `/pckcert` miss for a *known* platform first runs PCK cert selection
against the cached pool. Concurrent misses on the same key are de-duplicated.
`GET\|POST /refresh` is serialised.

### RocksDB memory

| CLI | env | TOML | default |
|-----|-----|------|---------|
| `--rocksdb-block-cache-mb` | `PCCS_ROCKSDB_BLOCK_CACHE_MB` | `rocksdb_block_cache_mb` | 8 |
| `--rocksdb-write-buffer-mb` | `PCCS_ROCKSDB_WRITE_BUFFER_MB` | `rocksdb_write_buffer_mb` | 64 |
| `--rocksdb-max-write-buffers` | | `rocksdb_max_write_buffers` | 2 |
| `--rocksdb-max-open-files` | | `rocksdb_max_open_files` | -1 |

## Debian package

Release artifacts: `pccs-rs_<version>_amd64.deb` plus a tarball.

The package installs:

| Path | What |
|------|------|
| `/usr/bin/pccs-rs` | binary |
| `/etc/pccs-rs/config.toml` | conffile; dpkg will not overwrite local edits |
| `/lib/systemd/system/pccs-rs.service` | unit |

The unit uses `DynamicUser=yes` and `StateDirectory=pccs-rs`, so RocksDB
lands in `/var/lib/pccs-rs`. It binds `127.0.0.1:8081` unless you change
`host` / `port`. An in-place upgrade restarts the unit if it was running.
`dpkg --purge` removes `/var/lib/pccs-rs` and `/var/lib/private/pccs-rs`.

Caddy / nginx stay outside this package.

## Development

[prek](https://prek.j178.dev) runs the same hooks locally and in CI:
trailing whitespace, EOF, YAML/TOML/JSON, merge conflicts, large files,
line endings, and `cargo fmt --all`.

```bash
# once per clone
prek install

# run every hook on the whole tree
prek run --all-files

cargo fmt --check --all
cargo test
cargo build --release
```

`prek install` writes Git hooks into `.git/hooks`. A commit that fails a hook
is rejected; formatters that rewrote files need a `git add` and a retry.
CI runs `cargo fmt --check --all` and `prek run --all-files` on every PR.

### Benchmarks

```bash
./scripts/bench.sh
```

Or:

```bash
cargo build --release --bin pccs-rs --bin loadgen
./target/release/pccs-rs serve --http --port 18081 --db-path /tmp/pccs-bench --uri '' --seed fixtures/seed.json &
./target/release/loadgen --url http://127.0.0.1:18081 --duration 5 --concurrency 32
```

Local dumps go to `compare/out/` (gitignored). Mix is 70% `/pckcert` /
20% `/tcb` / 10% `/qe/identity` against seeded v4 data.

RocksDB RSS measured **27.1 MiB** on a 5s HTTP cache-hit bench (32 conc,
135k rps) with the shipped defaults. Node vs Rust compare:
[`docs/compare-results.md`](docs/compare-results.md).

## Caching details

In every mode a `/pckcert` miss for a known platform first runs PCK cert
selection locally; only if that fails does LAZY go upstream and REQ / OFFLINE
answer 404. A CRL or TCB-info refresh the upstream cannot satisfy is a `503`.

In REQ mode, TCB levels Intel reports as `"Not available"` are written to the
registration queue with state `1`, readable via `GET /platforms?source=reg_na`.

Intel PCS uses `pckcerts` + in-memory PCK selection; a PCCS upstream is a
single GET. Intel has no `rootcacrl` route: the URL is taken from the Intel
root CA CRL Distribution Point, falling back to
`https://certificates.trustedservices.intel.com/IntelSGXRootCA.der`.

Accepted sockets get `TCP_NODELAY` and 60s `SO_KEEPALIVE`. Upstream sockets
get the same, plus a pool of up to `upstream_max_concurrent` idle connections
per host, dropped after `upstream_pool_idle_seconds` (0 disables pooling).

### RocksDB key layout

`{type-prefix}{cityhash128(canonical fields) hex}` — keys lowercase. Values
JSON.

| Prefix | Canonical fields | Value |
|--------|------------------|-------|
| `platform/` | qeid / pceid | whole PCK cert pool + fmspc, ca, enc_ppid, platform_manifest, issuer chain, known raw TCB levels |
| `pckcert/` | qeid / pceid / cpusvn / pcesvn | selected PEM + SGX-TCBm, FMSPC, CA, issuer chain |
| `tcb/` | sgx\|tdx / version / fmspc / update | TCB JSON + issuer chain |
| `identity/` | qe\|qve\|tdqe / version / update | identity JSON + issuer chain |
| `pckcrl/` | ca | CRL bytes + issuer chain |
| `rootcacrl` | (literal) | CRL bytes |
| `crl/` | uri | CRL bytes |
| `amd-kds/` | complete upstream URL | response bytes, content headers, fetch time |
| `appraisal/` | fmspc | policy list (GET joins defaults) |
| `preg/` | qeid / pceid / cpusvn / pcesvn | registration queue |

Every read re-checks the stored record against the key it was fetched with; a
mismatch is a miss. Writes that Intel wrapped in a SQL transaction use a
RocksDB `WriteBatch`.

Databases written before `platform/` have `pckcert/` records but no platform
records. `GET /platforms?source=[fmspc]` is empty until platforms are
re-registered, re-seeded, supplied via `PUT /platformcollateral`, or — in
LAZY — fetched on first request. Exact-key `pckcert/` hits still work.
REQ / OFFLINE answer `461` for those platforms until refilled.

## What is implemented

- All 30 default v4 routes (SGX v3 + v4 + TDX v4), mounted at
  `/sgx/certification/v3`, `/sgx/certification/v4`, and `/tdx/certification/v4`
- AMD KDS-compatible `GET /vcek/{*path}` and `GET /vlek/{*path}` (VCEK, VLEK,
  `cert_chain`, and `crl`), forwarding path and query to `kdsintf.amd.com`
- Auth, Request-ID (always freshly generated), v3 Warning, Intel headers,
  `text/html` error bodies, body limit (413 `Content too large.`),
  `x-powered-by` not set
- LAZY / REQ / OFFLINE, real upstream client, cron refresh
- `POST /platforms` (JSON **object** only; arrays are `400`), `GET /platforms`
  (`reg` / `reg_na` / `[fmspc,…]`)
- `PUT /platformcollateral`, validated against
  `PLATFORM_COLLATERAL_SCHEMA_V3` / `_V4`
- `GET|POST /refresh` (`type=certs` re-fetches each platform's pool)
- `PUT|GET /appraisalpolicy` (SHA-384 id, upsert by id, one default per fmspc)
- Full PCK cert selection: TCB is read from the certificate, never from
  `tcbm`; PCESVN is a full integer
- Platform registration by `platform_manifest`
- Duplicated query parameters take the first value; signed TCB-info /
  enclave-identity bodies are stored and returned byte-for-byte

## License

Apache License 2.0. See [LICENSE](LICENSE).
