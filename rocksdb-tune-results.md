# RocksDB memory-knob presets

Measured: 2026-08-21 22:08 CST (UTC+8) on this box.
Compiler: `rustc 1.98.0 (88d9e12ae 2026-08-18)`. Binaries: `cargo build --release` (`pccs-rs` + `loadgen`).

Load: HTTP, no TLS, cache-hit mix 70% `/pckcert` / 20% `/tcb` / 10% `/qe/identity`,
32 concurrency, 2 s warmup, 5 s timed. Fresh RocksDB dir + `fixtures/seed.json` per preset.
RSS = `VmRSS` from `/proc/<pid>/status` (idle after 2 s up; under-load sampled every 200 ms).
Ports 18181–18185, one server at a time, killed after each run.

| preset | block_cache_mb | write_buffer_mb | max_write_buffers | max_open_files | idle RSS (MiB) | under-load RSS min/med/max (MiB) | after-load RSS (MiB) | rps | p50 ms | p99 ms | errors |
|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|
| default | 8 | 64 | 2 | -1 | 22.7 | 22.7 / 26.8 / 26.8 | 26.8 | 139593.7 | 0.198 | 0.637 | 0 |
| tiny | 1 | 4 | 1 | 64 | 22.6 | 22.6 / 26.8 / 26.8 | 26.8 | 137287.6 | 0.202 | 0.639 | 0 |
| small | 2 | 8 | 2 | 128 | 22.6 | 22.6 / 26.8 / 26.8 | 26.8 | 135459.4 | 0.204 | 0.635 | 0 |
| medium | 8 | 16 | 2 | -1 | 22.7 | 22.7 / 26.8 / 26.8 | 26.8 | 136703.3 | 0.202 | 0.641 | 0 |
| large | 32 | 64 | 2 | -1 | 22.8 | 22.8 / 26.9 / 27.0 | 27.0 | 139054.2 | 0.199 | 0.627 | 0 |

## Takeaway

On this cache-hit GET workload the process does almost no writes after seed, so the 64 MiB write-buffer *cap* is not resident: default (8/64) after-load RSS is 26.8 MiB vs medium (8/16) 26.8 MiB (Δ 0.0 MiB) and tiny (1/4) 26.8 MiB. Idle RSS is already 22.7 MiB (tiny 22.6, large 22.8), so most of the previously reported ~27 MiB is process + librocksdb baseline, not a fully populated 8 MiB block cache or 64 MiB memtable. Raising the block cache to 32 MiB (`large`) moves after-load RSS to 27.0 MiB (+0.2 vs default); the extra is available cache capacity, not required for this tiny seed. Throughput stays in the same band (tiny 137288 / default 139594 / large 139054 rps) — the seed working set is far smaller than even the 1 MiB cache.

## Flags used

```
--rocksdb-block-cache-mb / PCCS_ROCKSDB_BLOCK_CACHE_MB / RocksDbBlockCacheMb   default 8
--rocksdb-write-buffer-mb / PCCS_ROCKSDB_WRITE_BUFFER_MB / RocksDbWriteBufferMb default 64
--rocksdb-max-write-buffers / RocksDbMaxWriteBuffers                           default 2
--rocksdb-max-open-files / RocksDbMaxOpenFiles                                 default -1
```
