# Intel Node PCCS vs pccs-rs — throughput and memory

Measured: 2026-08-21 21:01 CST (UTC+8) on this box (8 CPUs, 15 GiB RAM).

**Node served HTTP 200s for all three cache-hit GETs: yes.**

## How each server was run

### Node (Intel PCCS 1.27.0)

- Work dir: `/workspace/pccs-rs/compare/node-run` (config, `ssl_key/`, `pckcache.db`). Intel source was not edited (only `service/logs/` created for winston).
- Bind: `127.0.0.1:18082` **HTTPS** (self-signed `openssl req -x509` into the work dir).
- `CachingFillMode=LAZY`, `uri=https://pccs.phala.network/sgx/certification/v4/`.
- Tokens: SHA-512 of `user` / `admin` (same as Rust defaults).
- Seed:
  - LAZY warmup `GET /tcb?fmspc=00A067110000` and `GET /qe/identity` fetched **real** collateral from the Phala mirror (200 + issuer-chain headers) and cached it in sqlite.
  - Phala `GET /pckcert` for an unknown platform returns **400**; `GET /platforms` is **401** (no admin token). A real Intel sample PCK leaf + processor CA (dcap-qvl, FMSPC `00A067110000`) was inserted into sqlite so the cache-hit GET returns 200 with the same query params.
- Extra work vs Rust: Express + morgan + Sequelize/sqlite joins on every GET; V8 + 75 MiB `node_modules`; Node is effectively one JS thread.

### Rust (pccs-rs v1)

- HTTP: `--http --port 18081 --cache-mode offline --seed compare/seed.json`
- HTTPS: `--https --port 18083` with existing `certs/file.crt` + `certs/private.pem` (rustls)
- Same seed as Node: Phala TCB JSON (5510 B) + QE identity (1380 B) + sample PCK cert (1639 B). In-memory DashMap, no sqlite.
- Multi-threaded Tokio.

### Load

- Mix: 70% `GET /pckcert`, 20% `GET /tcb`, 10% `GET /qe/identity`
- Params: `qeid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` `cpusvn=0B0D0202FF010C000000000000000000` `pcesvn=000D` `pceid=0000` `fmspc=00A067110000`
- Concurrency **32**, warmup **2s**, durations **5s** and **15s**. Same `loadgen` (`--insecure` for HTTPS).
- RSS sampled every 200 ms via `/proc/<pid>/status`.

## Probe of https://pccs.phala.network

- TLS: HTTP/2, Caddy in front of Express (`x-powered-by`). Path prefix `/sgx/certification/v4/` is correct.
- `GET /qe/identity` → **200**, no token.
- `GET /tcb?fmspc=00A067110000` (and `00906ED50000`) → **200**, no token, `TCB-Info-Issuer-Chain` present.
- `GET /pckcert?...` (unknown platform) → **400** `Invalid request parameters.`
- `GET /platforms` → **401** (needs `admin-token`; we do not have one).
- `GET /pckcrl` and `/rootcacrl` → **500**.
- Did **not** call Intel PCS.

## Results

A) **Rust HTTP vs Node HTTPS** is mixed-transport (not apples-to-apples for rps).
B) **Rust HTTPS vs Node HTTPS** is the fair TLS comparison.
Memory is valid in both.

| Server | Transport | Idle RSS | Idle VmSize / VmPeak | Under-load RSS min/med/max | After RSS | rps | p50 ms | p99 ms | requests (ok/err) | 200s |
|---|---|---:|---|---|---:|---:|---:|---:|---|---|
| Rust | HTTP :18081 (5s) | 7104 KiB (6.9 MiB) | 551064 / 616056 KiB | 10756 / 12776 / 12856 KiB | 12848 KiB | 125206.4 | 0.226 | 0.703 | 626177 / 0 | yes |
| Rust | HTTPS :18083 (5s) | 8164 KiB (8.0 MiB) | 618652 / 747080 KiB | 11084 / 13740 / 13912 KiB | 13788 KiB | 113387.6 | 0.247 | 0.778 | 567083 / 0 | yes |
| Node | HTTPS :18082 (5s) | 115020 KiB (112.3 MiB) | 1350748 / 1440716 KiB | 115532 / 157636 / 208660 KiB | 208660 KiB | 1034.5 | 35.725 | 51.069 | 5194 / 0 | yes |
| Rust | HTTP (15s) | — (already warm) | 551596 / 616056 | 12916 / 13308 / 13348 KiB | 13312 KiB | 124447.0 | 0.226 | 0.720 | 1866844 / 0 | yes |
| Rust | HTTPS (15s) | — (already warm) | 618652 / 747080 | 13844 / 14380 / 14396 KiB | 14084 KiB | 114683.2 | 0.243 | 0.784 | 1720390 / 0 | yes |
| Node | HTTPS (15s) | — (already warm, ~204 MiB) | 1444040 / 1482260 | 208740 / 236440 / 246280 KiB | 236440 KiB | 1142.5 | 32.970 | 47.795 | 17159 / 0 | yes |

Fair HTTPS (5s): **Rust 113.4k rps vs Node 1.03k rps (~110×)**. p50 0.25 ms vs 35.7 ms.
Idle RSS: **Rust HTTPS 8.0 MiB vs Node 112.3 MiB (~14×)**. Under 5s load max: 13.6 MiB vs 203.8 MiB.

### Idle `ps` (after ~2s up, before that process's first timed load)

```
# Node (true idle after seed, before any loadgen)
PID 634038  RSS=115020  VSZ=1350748  %CPU=1.0  %MEM=0.7  node pccs_server.js
VmRSS=115020  VmSize=1350748  VmPeak=1440716  VmHWM=133824  (KiB)

# Rust HTTP (true idle after seed)
PID 636000  RSS=7104  VSZ=551064  VmHWM=7104  (KiB)

# Rust HTTPS (true idle after seed)
PID 636670  RSS=8164  VSZ=618652  VmHWM=8164  (KiB)
```

`ps` `%CPU` after the 5s run (lifetime average, includes idle): Node 9.7%, Rust HTTP 129%, Rust HTTPS 138%. Rust saturates multiple cores; Node's event loop is one core.

### On-disk

- Node `node_modules`: **75 MiB** (mapped into the process; contributes to VmSize / file RSS).
- Rust `target/release/pccs-rs`: single binary (~7.7 MiB).
- Shared seed JSON: ~32 KiB.

## Caveats

- Rust v1 is **in-memory DashMap**; Node uses **SQLite + Sequelize** (multi-table join on every `/pckcert`). That is a real architecture gap, not just language.
- Node TLS is OpenSSL (restricted sigalgs); Rust TLS is rustls/ring. Same protocol, different stacks.
- Seed is one platform + one FMSPC TCB + one QE identity + one PCK cert — not a full production cache.
- Node LAZY warmup contacted Phala once for tcb/identity; timed runs are cache hits only (no Intel PCS).
- Phala could not supply a live `/pckcert` platform id (no admin token). PCK body is a real Intel sample cert; TCB and QE identity are live Phala responses. All three body sizes matched on both servers (1639 / 5510 / 1380 bytes).
- Node 15s RSS starts from the post-5s heap (~204 MiB), not true idle — V8 did not return memory. Rust RSS stays flat.
- Node `LogLevel=error`; Rust tracing `info`.

## Memory takeaway

Idle RSS is the clean comparison: after seed, Node sits at **112 MiB** (V8 + mapped `node_modules` + libsqlite3) while Rust HTTPS is **8 MiB** and Rust HTTP **6.9 MiB** — about **14×** less resident memory for the same three cache-hit documents. Under a 32-way load Node grows to **204–240 MiB** (V8 heap + buffers) and does not shrink; Rust moves from ~8 MiB to a tight **13–14 MiB** band and stays there on the 15s run. The collateral itself is tens of KiB; almost all of Node's footprint is runtime baseline, not cache contents.

