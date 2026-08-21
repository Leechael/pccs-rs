#!/usr/bin/env python3
"""Sample VmRSS / VmSize / VmPeak for a PID every 200ms."""
import argparse
import statistics
import sys
import time
from pathlib import Path


def read_status(pid: int):
    p = Path(f"/proc/{pid}/status")
    if not p.exists():
        return None
    out = {}
    for line in p.read_text().splitlines():
        if line.startswith(("VmRSS:", "VmSize:", "VmPeak:", "VmHWM:")):
            parts = line.split()
            out[parts[0].rstrip(":")] = int(parts[1])  # KiB
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pid", type=int)
    ap.add_argument("--interval", type=float, default=0.2)
    ap.add_argument("--seconds", type=float, default=0)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    samples = []
    t0 = time.time()
    while True:
        st = read_status(args.pid)
        if st is None:
            break
        st["t"] = time.time() - t0
        samples.append(st)
        if args.seconds and (time.time() - t0) >= args.seconds:
            break
        time.sleep(args.interval)
    if not samples:
        print("no samples", file=sys.stderr)
        sys.exit(1)
    rss = [s["VmRSS"] for s in samples]
    rss.sort()
    mid = rss[len(rss) // 2]
    summary = {
        "pid": args.pid,
        "n": len(samples),
        "rss_kib_min": min(rss),
        "rss_kib_median": mid,
        "rss_kib_max": max(rss),
        "rss_kib_mean": int(statistics.mean(rss)),
        "vmsize_kib_last": samples[-1].get("VmSize"),
        "vmpeak_kib_last": samples[-1].get("VmPeak"),
        "vmhwm_kib_last": samples[-1].get("VmHWM"),
        "first": samples[0],
        "last": samples[-1],
    }
    import json
    text = json.dumps(summary, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text)


if __name__ == "__main__":
    main()
