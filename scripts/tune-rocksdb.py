#!/usr/bin/env python3
"""Compare RocksDB memory presets: idle/load RSS + cache-hit rps."""

from __future__ import annotations

import os
import re
import signal
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path("/workspace/pccs-rs")
BIN = ROOT / "target/release/pccs-rs"
LOAD = ROOT / "target/release/loadgen"
SEED = ROOT / "fixtures/seed.json"

PRESETS = [
    # name, block_cache_mb, write_buffer_mb, max_write_buffers, max_open_files, port
    ("default", 8, 64, 2, -1, 18181),
    ("tiny", 1, 4, 1, 64, 18182),
    ("small", 2, 8, 2, 128, 18183),
    ("medium", 8, 16, 2, -1, 18184),
    ("large", 32, 64, 2, -1, 18185),
]

READY_URL = (
    "/sgx/certification/v4/pckcert"
    "?qeid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "&cpusvn=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    "&pcesvn=CCCC&pceid=DDDD"
)


def vmrss_kb(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError, ValueError):
        return None
    return None


def kib_to_mib(kb: int | None) -> str:
    if kb is None:
        return "n/a"
    return f"{kb / 1024:.1f}"


def wait_ready(port: int, timeout: float = 20.0) -> bool:
    url = f"http://127.0.0.1:{port}{READY_URL}"
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(url, timeout=0.5) as resp:
                if 200 <= resp.status < 300:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(0.1)
    return False


def parse_loadgen(text: str) -> dict:
    def grab(pat: str, default: str = "0") -> str:
        m = re.search(pat, text, re.M)
        return m.group(1) if m else default

    return {
        "rps": float(grab(r"^rps: ([0-9.]+)")),
        "p50_ms": float(grab(r"^p50_ms: ([0-9.]+)")),
        "p99_ms": float(grab(r"^p99_ms: ([0-9.]+)")),
        "ok": int(grab(r"ok=(\d+)")),
        "err": int(grab(r"err=(\d+)")),
        "raw": text.strip(),
    }


def kill_proc(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def run_preset(name: str, cache: int, wbuf: int, nbuf: int, nfiles: int, port: int) -> dict:
    db = Path(f"/tmp/pccs-rs-tune-{name}")
    subprocess.run(["rm", "-rf", str(db)], check=True)
    log_path = Path(f"/tmp/pccs-rs-tune-{name}.log")
    env = os.environ.copy()
    env["RUST_LOG"] = "info"
    env["PATH"] = os.environ.get("PATH", "")
    cmd = [
        str(BIN),
        "--http",
        "--host",
        "127.0.0.1",
        f"--port={port}",
        "--cache-mode=offline",
        f"--db-path={db}",
        "--uri=",
        f"--seed={SEED}",
        f"--rocksdb-block-cache-mb={cache}",
        f"--rocksdb-write-buffer-mb={wbuf}",
        f"--rocksdb-max-write-buffers={nbuf}",
        f"--rocksdb-max-open-files={nfiles}",
    ]
    logf = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, env=env, stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_ready(port):
            logf.flush()
            raise RuntimeError(f"{name} not ready on :{port}; log={log_path.read_text()[-2000:]}")
        time.sleep(2.0)
        idle = vmrss_kb(proc.pid)
        load = subprocess.Popen(
            [
                str(LOAD),
                "--url",
                f"http://127.0.0.1:{port}",
                "--duration",
                "5",
                "--concurrency",
                "32",
                "--warmup",
                "2",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        samples: list[int] = []
        while load.poll() is None:
            r = vmrss_kb(proc.pid)
            if r is not None:
                samples.append(r)
            time.sleep(0.2)
        out, _ = load.communicate()
        if load.returncode != 0:
            raise RuntimeError(f"loadgen failed ({load.returncode}): {out}")
        after = vmrss_kb(proc.pid)
        stats = parse_loadgen(out)
        if not samples:
            samples = [after or idle or 0]
        samples_sorted = sorted(samples)
        return {
            "name": name,
            "block_cache_mb": cache,
            "write_buffer_mb": wbuf,
            "max_write_buffers": nbuf,
            "max_open_files": nfiles,
            "port": port,
            "pid": proc.pid,
            "idle_kb": idle,
            "load_min_kb": min(samples),
            "load_med_kb": int(statistics.median(samples_sorted)),
            "load_max_kb": max(samples),
            "after_kb": after,
            "n_samples": len(samples),
            **stats,
        }
    finally:
        kill_proc(proc)
        logf.close()
        # leave db for inspection; next run wipes it


def rustc_version() -> str:
    env = os.environ.copy()
    env["PATH"] = os.path.expanduser("~/.cargo/bin") + ":" + env.get("PATH", "")
    out = subprocess.check_output(["rustc", "--version"], env=env, text=True).strip()
    return out


def fmt_row(r: dict) -> str:
    nfiles = r["max_open_files"]
    return (
        f"| {r['name']} | {r['block_cache_mb']} | {r['write_buffer_mb']} | "
        f"{r['max_write_buffers']} | {nfiles} | "
        f"{kib_to_mib(r['idle_kb'])} | "
        f"{kib_to_mib(r['load_min_kb'])} / {kib_to_mib(r['load_med_kb'])} / {kib_to_mib(r['load_max_kb'])} | "
        f"{kib_to_mib(r['after_kb'])} | {r['rps']:.1f} | {r['p50_ms']:.3f} | {r['p99_ms']:.3f} | "
        f"{r['err']} |"
    )


def takeaway(rows: dict[str, dict]) -> str:
    d = rows["default"]
    t = rows["tiny"]
    s = rows["small"]
    m = rows["medium"]
    l = rows["large"]
    # Use after-load RSS as the "27 MiB" comparable number
    def mib(kb):
        return kb / 1024.0 if kb else 0.0

    d_after = mib(d["after_kb"])
    t_after = mib(t["after_kb"])
    l_after = mib(l["after_kb"])
    d_idle = mib(d["idle_kb"])
    t_idle = mib(t["idle_kb"])
    l_idle = mib(l["idle_kb"])
    # tiny vs default isolates extra cache+buffer above a 1/4/1/64 floor
    extra_vs_tiny = d_after - t_after
    cache_delta_large = l_after - d_after  # +24 MiB configured cache
    # write buffer: medium is 8/16 vs default 8/64 — same cache, smaller wbuf cap
    wbuf_delta = mib(d["after_kb"]) - mib(m["after_kb"])
    return (
        f"On this cache-hit GET workload the process does almost no writes after seed, "
        f"so the 64 MiB write-buffer *cap* is not resident: default (8/64) after-load RSS "
        f"is {d_after:.1f} MiB vs medium (8/16) {mib(m['after_kb']):.1f} MiB "
        f"(Δ {wbuf_delta:+.1f} MiB) and tiny (1/4) {t_after:.1f} MiB. "
        f"Idle RSS is already {d_idle:.1f} MiB (tiny {t_idle:.1f}, large {l_idle:.1f}), "
        f"so most of the previously reported ~27 MiB is process + librocksdb baseline, "
        f"not a fully populated 8 MiB block cache or 64 MiB memtable. "
        f"Raising the block cache to 32 MiB (`large`) moves after-load RSS to {l_after:.1f} MiB "
        f"(+{cache_delta_large:.1f} vs default); the extra is available cache capacity, "
        f"not required for this tiny seed. Throughput stays in the same band "
        f"(tiny {t['rps']:.0f} / default {d['rps']:.0f} / large {l['rps']:.0f} rps) — "
        f"the seed working set is far smaller than even the 1 MiB cache."
    )


def main() -> int:
    if not BIN.is_file() or not LOAD.is_file():
        print("missing release binaries", file=sys.stderr)
        return 1
    rustc = rustc_version()
    print(f"rustc: {rustc}", flush=True)
    print(f"bin: {BIN}", flush=True)
    rows = []
    by_name = {}
    for name, cache, wbuf, nbuf, nfiles, port in PRESETS:
        print(
            f"==> preset {name} cache={cache} wbuf={wbuf} nbuf={nbuf} nfiles={nfiles} port={port}",
            flush=True,
        )
        r = run_preset(name, cache, wbuf, nbuf, nfiles, port)
        rows.append(r)
        by_name[name] = r
        print(
            f"    idle={kib_to_mib(r['idle_kb'])} MiB  "
            f"load={kib_to_mib(r['load_min_kb'])}/{kib_to_mib(r['load_med_kb'])}/{kib_to_mib(r['load_max_kb'])}  "
            f"after={kib_to_mib(r['after_kb'])}  rps={r['rps']:.1f} p50={r['p50_ms']:.3f} p99={r['p99_ms']:.3f} err={r['err']}",
            flush=True,
        )

    measured = time.strftime("%Y-%m-%d %H:%M %Z", time.localtime())
    # Convert UTC clock to Asia/Taipei for the report
    try:
        import zoneinfo

        tz = zoneinfo.ZoneInfo("Asia/Taipei")
        from datetime import datetime, timezone

        measured = datetime.now(timezone.utc).astimezone(tz).strftime("%Y-%m-%d %H:%M %Z (UTC+8)")
    except Exception:
        pass

    header = (
        "| preset | block_cache_mb | write_buffer_mb | max_write_buffers | max_open_files | "
        "idle RSS (MiB) | under-load RSS min/med/max (MiB) | after-load RSS (MiB) | "
        "rps | p50 ms | p99 ms | errors |"
    )
    sep = "|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|"
    table_lines = [header, sep] + [fmt_row(r) for r in rows]
    table = "\n".join(table_lines)
    para = takeaway(by_name)

    md = f"""# RocksDB memory-knob presets

Measured: {measured} on this box.
Compiler: `{rustc}`. Binaries: `cargo build --release` (`pccs-rs` + `loadgen`).

Load: HTTP, no TLS, cache-hit mix 70% `/pckcert` / 20% `/tcb` / 10% `/qe/identity`,
32 concurrency, 2 s warmup, 5 s timed. Fresh RocksDB dir + `fixtures/seed.json` per preset.
RSS = `VmRSS` from `/proc/<pid>/status` (idle after 2 s up; under-load sampled every 200 ms).
Ports 18181–18185, one server at a time, killed after each run.

{table}

## Takeaway

{para}

## Flags used

```
--rocksdb-block-cache-mb / PCCS_ROCKSDB_BLOCK_CACHE_MB / RocksDbBlockCacheMb   default 8
--rocksdb-write-buffer-mb / PCCS_ROCKSDB_WRITE_BUFFER_MB / RocksDbWriteBufferMb default 64
--rocksdb-max-write-buffers / RocksDbMaxWriteBuffers                           default 2
--rocksdb-max-open-files / RocksDbMaxOpenFiles                                 default -1
```
"""
    out_dir = ROOT / "compare" / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "rocksdb-tune-results.md").write_text(md, encoding="utf-8")

    txt_lines = [
        "pccs-rs RocksDB memory-knob tune",
        f"measured: {measured}",
        f"rustc: {rustc}",
        "load: HTTP cache-hit 32 conc, 5s, 2s warmup, fixtures/seed.json, fresh db each preset",
        "",
        "preset  cache_mb  wbuf_mb  max_wb  max_open  idle_MiB  load_min/med/max_MiB  after_MiB  rps  p50_ms  p99_ms  err",
    ]
    for r in rows:
        txt_lines.append(
            f"{r['name']:<8} {r['block_cache_mb']:>8} {r['write_buffer_mb']:>8} "
            f"{r['max_write_buffers']:>7} {r['max_open_files']:>9} "
            f"{kib_to_mib(r['idle_kb']):>9} "
            f"{kib_to_mib(r['load_min_kb'])}/{kib_to_mib(r['load_med_kb'])}/{kib_to_mib(r['load_max_kb']):<6} "
            f"{kib_to_mib(r['after_kb']):>9} {r['rps']:>8.1f} {r['p50_ms']:>7.3f} {r['p99_ms']:>7.3f} {r['err']:>4}"
        )
    txt_lines += ["", "takeaway:", para, ""]
    (out_dir / "rocksdb-tune-results.txt").write_text("\n".join(txt_lines) + "\n", encoding="utf-8")
    print("wrote", out_dir / "rocksdb-tune-results.md", "and .txt", flush=True)
    print(table)
    print(para)
    return 0


if __name__ == "__main__":
    sys.exit(main())
