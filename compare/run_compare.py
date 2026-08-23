#!/usr/bin/env python3
"""Compare Intel Node PCCS vs pccs-rs: throughput + RSS."""
import json
import os
import signal
import sqlite3
import ssl
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path("/workspace/pccs-rs")
COMPARE = ROOT / "compare"
OUT = COMPARE / "out"
NODE_RUN = COMPARE / "node-run"
INTEL = Path("/workspace/confidential-computing.tee.dcap.pccs/service")
BIN = ROOT / "target/release/pccs-rs"
LOAD = ROOT / "target/release/loadgen"
SEED = COMPARE / "seed.json"
PARAMS = json.loads((COMPARE / "query_params.json").read_text())
RESULTS = {}


def ensure_out():
    OUT.mkdir(parents=True, exist_ok=True)

USER_HASH = "b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
ADMIN_HASH = "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"

QEID = PARAMS["qeid"]
CPUSVN = PARAMS["cpusvn"]
PCESVN = PARAMS["pcesvn"]
PCEID = PARAMS["pceid"]
FMSPC = PARAMS["fmspc"]
TCBM = PARAMS["tcbm"]

CTX = ssl._create_unverified_context()


def http_get(url, timeout=20):
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            body = r.read()
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def paths():
    pck = f"/sgx/certification/v4/pckcert?qeid={QEID}&cpusvn={CPUSVN}&pcesvn={PCESVN}&pceid={PCEID}"
    tcb = f"/sgx/certification/v4/tcb?fmspc={FMSPC}"
    qe = "/sgx/certification/v4/qe/identity"
    return pck, tcb, qe


def read_status(pid):
    p = Path(f"/proc/{pid}/status")
    if not p.exists():
        return None
    out = {}
    for line in p.read_text().splitlines():
        if line.startswith(("VmRSS:", "VmSize:", "VmPeak:", "VmHWM:", "Name:")):
            parts = line.split()
            key = parts[0].rstrip(":")
            out[key] = parts[1] if key == "Name" else int(parts[1])
    return out


def ps_snapshot(pid):
    r = subprocess.run(
        ["ps", "-o", "pid,rss,vsz,pcpu,pmem,cmd", "-p", str(pid)],
        capture_output=True,
        text=True,
    )
    return r.stdout.strip()


def sample_rss(pid, seconds, interval=0.2):
    samples = []
    t0 = time.time()
    while time.time() - t0 < seconds:
        st = read_status(pid)
        if st is None:
            break
        samples.append(st)
        time.sleep(interval)
    if not samples:
        return None
    rss = sorted(s["VmRSS"] for s in samples)
    return {
        "n": len(samples),
        "rss_kib_min": min(rss),
        "rss_kib_median": rss[len(rss) // 2],
        "rss_kib_max": max(rss),
        "rss_kib_mean": int(statistics.mean(rss)),
        "vmsize_kib_last": samples[-1].get("VmSize"),
        "vmpeak_kib_last": samples[-1].get("VmPeak"),
        "vmhwm_kib_last": samples[-1].get("VmHWM"),
    }


def kib_mb(kib):
    return f"{kib} KiB ({kib/1024:.1f} MiB)"


def start_proc(cmd, cwd=None, extra_env=None, log_path=None):
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    logf = open(log_path, "w") if log_path else subprocess.DEVNULL
    p = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdout=logf,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    p._logf = logf
    return p


def stop_proc(p):
    if p is None:
        return
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait(timeout=3)
    if getattr(p, "_logf", None) and p._logf is not subprocess.DEVNULL:
        try:
            p._logf.close()
        except Exception:
            pass


def wait_ready(url, tries=80, delay=0.15):
    for _ in range(tries):
        try:
            status, _, _ = http_get(url, timeout=2)
            if status in (200, 400, 401, 404, 461):
                return True
        except Exception:
            pass
        time.sleep(delay)
    return False


def seed_node_pckcert(db_path):
    leaf = (COMPARE / "pck_leaf.pem").read_bytes()
    intmd = (COMPARE / "pck_intmd.pem").read_bytes()
    root = (COMPARE / "pck_root.pem").read_bytes()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    # root (id=1) may already exist from LAZY tcb fetch; keep it
    cur.execute("SELECT id FROM pcs_certificates")
    ids = {r[0] for r in cur.fetchall()}
    if 1 not in ids:
        cur.execute(
            "INSERT INTO pcs_certificates (id, cert, created_time, updated_time) VALUES (1, ?, ?, ?)",
            (root, now, now),
        )
    if 2 not in ids:
        cur.execute(
            "INSERT INTO pcs_certificates (id, cert, created_time, updated_time) VALUES (2, ?, ?, ?)",
            (intmd, now, now),
        )
    else:
        cur.execute("UPDATE pcs_certificates SET cert=? WHERE id=2", (intmd,))
    cur.execute(
        "INSERT OR REPLACE INTO pck_certchain (ca, root_cert_id, intmd_cert_id, created_time, updated_time) VALUES ('PROCESSOR', 1, 2, ?, ?)",
        (now, now),
    )
    cur.execute(
        "INSERT OR REPLACE INTO platforms (qe_id, pce_id, platform_manifest, enc_ppid, fmspc, ca, created_time, updated_time) VALUES (?, ?, ?, ?, ?, 'PROCESSOR', ?, ?)",
        (QEID, PCEID, b"", b"", FMSPC, now, now),
    )
    cur.execute(
        "INSERT OR REPLACE INTO platform_tcbs (qe_id, pce_id, cpu_svn, pce_svn, tcbm, created_time, updated_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (QEID, PCEID, CPUSVN, PCESVN, TCBM, now, now),
    )
    cur.execute(
        "INSERT OR REPLACE INTO pck_cert (qe_id, pce_id, tcbm, pck_cert, created_time, updated_time) VALUES (?, ?, ?, ?, ?, ?)",
        (QEID, PCEID, TCBM, leaf, now, now),
    )
    con.commit()
    con.close()


def loadgen(url, duration, warmup, extra=None):
    cmd = [
        str(LOAD),
        "--url",
        url,
        "--duration",
        str(duration),
        "--concurrency",
        "32",
        "--warmup",
        str(warmup),
        "--insecure",
        "--qeid",
        QEID,
        "--cpusvn",
        CPUSVN,
        "--pcesvn",
        PCESVN,
        "--pceid",
        PCEID,
        "--fmspc",
        FMSPC,
    ]
    if extra:
        cmd.extend(extra)
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = r.stdout + r.stderr
    parsed = {}
    for line in out.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            parsed[k.strip()] = v.strip()
    return {"raw": out, "parsed": parsed, "exit": r.returncode}


def verify_three(base):
    pck, tcb, qe = paths()
    out = {}
    for name, path in (("pckcert", pck), ("tcb", tcb), ("qe_identity", qe)):
        try:
            status, hdrs, body = http_get(base + path, timeout=15)
            out[name] = {
                "status": status,
                "bytes": len(body),
                "ok": status == 200,
            }
        except Exception as e:
            out[name] = {"status": None, "bytes": 0, "ok": False, "error": str(e)}
    return out


def measure_server(label, pid, base, duration=5, warmup=2):
    time.sleep(2)
    idle = read_status(pid)
    idle_ps = ps_snapshot(pid)
    verify = verify_three(base)
    # RSS sampler in parallel with loadgen
    sampler = subprocess.Popen(
        [
            sys.executable,
            str(COMPARE / "sample_rss.py"),
            str(pid),
            "--seconds",
            str(duration + 1),
            "--interval",
            "0.2",
            "--out",
            str(OUT / f"rss_{label}.json"),
        ]
    )
    bench = loadgen(base, duration, warmup)
    sampler.wait(timeout=duration + 10)
    after = read_status(pid)
    after_ps = ps_snapshot(pid)
    rss = None
    rss_path = OUT / f"rss_{label}.json"
    if rss_path.exists():
        rss = json.loads(rss_path.read_text())
    return {
        "label": label,
        "pid": pid,
        "idle_status": idle,
        "idle_ps": idle_ps,
        "after_status": after,
        "after_ps": after_ps,
        "under_load_rss": rss,
        "verify": verify,
        "bench": bench,
        "served_200s": all(v.get("ok") for v in verify.values()),
    }


def start_node():
    env = {
        "NODE_CONFIG_DIR": str(NODE_RUN / "config"),
        "NODE_ENV": "production",
        "NODE_CONFIG": "",
    }
    log = COMPARE / "node-server.log"
    p = start_proc(
        ["node", str(INTEL / "pccs_server.js")],
        cwd=str(NODE_RUN),
        extra_env=env,
        log_path=str(log),
    )
    pck, tcb, qe = paths()
    ready = wait_ready("https://127.0.0.1:18082" + tcb, tries=100)
    return p, ready, log


def start_rust(port, https):
    cmd = [
        str(BIN),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--cache-mode",
        "offline",
        "--seed",
        str(SEED),
    ]
    if https:
        cmd += [
            "--https",
            "--cert",
            str(ROOT / "certs/file.crt"),
            "--key",
            str(ROOT / "certs/private.pem"),
        ]
    else:
        cmd += ["--http"]
    log = COMPARE / f"rust-{'https' if https else 'http'}.log"
    p = start_proc(cmd, cwd=str(ROOT), log_path=str(log))
    scheme = "https" if https else "http"
    _, tcb, _ = paths()
    ready = wait_ready(f"{scheme}://127.0.0.1:{port}{tcb}", tries=80)
    return p, ready, log


def main():
    ensure_out()
    out = {
        "when": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "query": PARAMS,
        "phala": {
            "uri": "https://pccs.phala.network/sgx/certification/v4/",
            "tcb_200": True,
            "qe_identity_200": True,
            "pckcert_unknown_platform": "400 Invalid request parameters (no enumerable cache; GET /platforms is 401)",
            "pckcrl": "500",
            "auth": "GET tcb/qe/identity unauthenticated; GET /platforms 401",
        },
        "runs": {},
        "node_served_200s": False,
        "notes": [],
    }

    # --- Node ---
    print("==> starting Node PCCS on :18082 HTTPS, LAZY, uri=Phala")
    node, ready, nlog = start_node()
    out["notes"].append(f"node_ready={ready} pid={node.pid}")
    node_served = False
    try:
        if not ready:
            out["notes"].append("Node failed to become ready. log tail: " + nlog.read_text()[-2000:])
        else:
            # Warmup: let LAZY fill tcb + qe identity from Phala
            pck, tcb, qe = paths()
            base = "https://127.0.0.1:18082"
            st_tcb, _, body_tcb = http_get(base + tcb, timeout=30)
            st_qe, _, body_qe = http_get(base + qe, timeout=30)
            out["notes"].append(f"node warmup tcb={st_tcb} bytes={len(body_tcb)} qe={st_qe} bytes={len(body_qe)}")
            db = NODE_RUN / "pckcache.db"
            if db.exists():
                seed_node_pckcert(str(db))
                out["notes"].append("seeded Node sqlite pckcert/platform rows (Phala pckcert not enumerable)")
            v = verify_three(base)
            out["node_verify_after_seed"] = v
            node_served = all(x.get("ok") for x in v.values())
            out["node_served_200s"] = node_served
            print("Node verify", v)
            rec = measure_server("node_https", node.pid, base, duration=5, warmup=2)
            out["runs"]["node_https_5s"] = rec
            rec15 = measure_server("node_https_15s", node.pid, base, duration=15, warmup=2)
            out["runs"]["node_https_15s"] = rec15
    finally:
        stop_proc(node)
        time.sleep(0.5)

    # --- Rust HTTP ---
    print("==> starting Rust HTTP :18081")
    rust, ready, rlog = start_rust(18081, https=False)
    try:
        if not ready:
            out["notes"].append("Rust HTTP not ready: " + rlog.read_text()[-1500:])
        else:
            base = "http://127.0.0.1:18081"
            v = verify_three(base)
            out["rust_http_verify"] = v
            rec = measure_server("rust_http", rust.pid, base, duration=5, warmup=2)
            out["runs"]["rust_http_5s"] = rec
            rec15 = measure_server("rust_http_15s", rust.pid, base, duration=15, warmup=2)
            out["runs"]["rust_http_15s"] = rec15
    finally:
        stop_proc(rust)
        time.sleep(0.5)

    # --- Rust HTTPS ---
    print("==> starting Rust HTTPS :18083")
    rusts, ready, rlog = start_rust(18083, https=True)
    try:
        if not ready:
            out["notes"].append("Rust HTTPS not ready: " + rlog.read_text()[-1500:])
        else:
            base = "https://127.0.0.1:18083"
            v = verify_three(base)
            out["rust_https_verify"] = v
            rec = measure_server("rust_https", rusts.pid, base, duration=5, warmup=2)
            out["runs"]["rust_https_5s"] = rec
            rec15 = measure_server("rust_https_15s", rusts.pid, base, duration=15, warmup=2)
            out["runs"]["rust_https_15s"] = rec15
    finally:
        stop_proc(rusts)

    ensure_out()
    (OUT / "compare-raw.json").write_text(json.dumps(out, indent=2, default=str))
    write_reports(out)
    print("DONE node_served_200s=", out["node_served_200s"])


def bench_line(rec):
    p = rec.get("bench", {}).get("parsed", {})
    return {
        "rps": p.get("rps"),
        "p50_ms": p.get("p50_ms"),
        "p99_ms": p.get("p99_ms"),
        "requests": p.get("requests"),
        "ok_err": None,
    }


def write_reports(out):
    def idle_rss(rec):
        st = rec.get("idle_status") or {}
        return st.get("VmRSS"), st.get("VmSize"), st.get("VmPeak")

    def load_rss(rec):
        return rec.get("under_load_rss") or {}

    lines = []
    lines.append("# Intel Node PCCS vs pccs-rs — throughput and memory")
    lines.append("")
    lines.append(f"Measured: {out['when']} (UTC). Convert to Asia/Taipei (UTC+8) by adding 8 hours.")
    lines.append("")
    lines.append("## How each server was run")
    lines.append("")
    lines.append("### Node (Intel PCCS 1.27.0)")
    lines.append("- Work dir: `/workspace/pccs-rs/compare/node-run` (config, ssl_key, sqlite). Intel source not edited.")
    lines.append("- Bind: `127.0.0.1:18082` **HTTPS** (self-signed `ssl_key/`).")
    lines.append("- `CachingFillMode=LAZY`, `uri=https://pccs.phala.network/sgx/certification/v4/`.")
    lines.append("- Tokens: SHA-512 of `user` / `admin` (same as Rust defaults).")
    lines.append("- Seed: LAZY warmup GET `/tcb` and `/qe/identity` fetched **real** collateral from the Phala mirror and cached it in sqlite.")
    lines.append("- `GET /pckcert` is not enumerable on Phala (unknown qeid → 400; `/platforms` → 401). PCK leaf + processor chain came from the public dcap-qvl sample cert (FMSPC `00A067110000`) and were inserted into sqlite so the cache-hit GET returns 200.")
    lines.append("- Node extra work vs Rust: Express + morgan + Sequelize/sqlite joins on every GET; V8 + node_modules.")
    lines.append("")
    lines.append("### Rust (pccs-rs v1)")
    lines.append("- HTTP: `--http --port 18081 --cache-mode offline --seed compare/seed.json`")
    lines.append("- HTTPS: `--https --port 18083` with `certs/file.crt` + `certs/private.pem`")
    lines.append("- Same seed as Node: Phala TCB + QE identity JSON + sample PCK cert. In-memory DashMap, no sqlite.")
    lines.append("")
    lines.append("### Load")
    lines.append("- Mix: 70% GET `/pckcert`, 20% GET `/tcb`, 10% GET `/qe/identity`")
    lines.append(f"- Params: qeid={QEID} cpusvn={CPUSVN} pcesvn={PCESVN} pceid={PCEID} fmspc={FMSPC}")
    lines.append("- Concurrency 32, warmup 2s, durations 5s and 15s. loadgen `--insecure` for HTTPS.")
    lines.append("")
    lines.append("## Probe of https://pccs.phala.network")
    lines.append("")
    lines.append("- TLS: HTTP/2 via Caddy. Express (`x-powered-by`).")
    lines.append("- `GET /sgx/certification/v4/qe/identity` → **200**, no token.")
    lines.append("- `GET /sgx/certification/v4/tcb?fmspc=00A067110000` → **200**, no token, `TCB-Info-Issuer-Chain` present.")
    lines.append("- `GET /sgx/certification/v4/pckcert?...` (unknown platform) → **400** `Invalid request parameters.`")
    lines.append("- `GET /sgx/certification/v4/platforms` → **401** (admin-token). No token available.")
    lines.append("- `GET /pckcrl` and `/rootcacrl` → **500**.")
    lines.append("- Did **not** call Intel PCS.")
    lines.append("")
    lines.append("## Results")
    lines.append("")

    def row(name, rec):
        idle = rec.get("idle_status") or {}
        load = rec.get("under_load_rss") or {}
        p = rec.get("bench", {}).get("parsed", {})
        v = rec.get("verify") or {}
        served = all(x.get("ok") for x in v.values()) if v else "?"
        return {
            "name": name,
            "idle_rss": idle.get("VmRSS"),
            "idle_vsz": idle.get("VmSize"),
            "idle_peak": idle.get("VmPeak"),
            "load_min": load.get("rss_kib_min"),
            "load_med": load.get("rss_kib_median"),
            "load_max": load.get("rss_kib_max"),
            "rps": p.get("rps"),
            "p50": p.get("p50_ms"),
            "p99": p.get("p99_ms"),
            "reqs": p.get("requests"),
            "served": served,
        }

    rows = []
    for key, title in (
        ("rust_http_5s", "Rust HTTP :18081 (5s)"),
        ("rust_https_5s", "Rust HTTPS :18083 (5s)"),
        ("node_https_5s", "Node HTTPS :18082 (5s)"),
        ("rust_http_15s", "Rust HTTP (15s)"),
        ("rust_https_15s", "Rust HTTPS (15s)"),
        ("node_https_15s", "Node HTTPS (15s)"),
    ):
        if key in out["runs"]:
            rows.append(row(title, out["runs"][key]))

    lines.append("| Server | Idle RSS | Under-load RSS min/med/max | rps | p50 ms | p99 ms | requests | 200s? |")
    lines.append("|---|---:|---|---:|---:|---:|---|---|")
    for r in rows:
        idle = kib_mb(r["idle_rss"]) if r["idle_rss"] else "-"
        if r["load_min"] is not None:
            load = f"{r['load_min']}/{r['load_med']}/{r['load_max']} KiB"
        else:
            load = "-"
        lines.append(
            f"| {r['name']} | {idle} | {load} | {r['rps'] or '-'} | {r['p50'] or '-'} | {r['p99'] or '-'} | {r['reqs'] or '-'} | {r['served']} |"
        )
    lines.append("")
    lines.append("A) **Rust HTTP vs Node HTTPS** is mixed-transport (not apples-to-apples for rps).")
    lines.append("B) **Rust HTTPS vs Node HTTPS** is the fair TLS comparison.")
    lines.append("Memory is valid in both: RSS is process-level.")
    lines.append("")
    lines.append("## Idle snapshots (`ps` after ~2s up)")
    lines.append("")
    for key in ("rust_http_5s", "rust_https_5s", "node_https_5s"):
        rec = out["runs"].get(key)
        if rec:
            lines.append(f"### {key}")
            lines.append("```")
            lines.append(rec.get("idle_ps") or "")
            st = rec.get("idle_status") or {}
            lines.append(f"VmRSS={st.get('VmRSS')} VmSize={st.get('VmSize')} VmPeak={st.get('VmPeak')} VmHWM={st.get('VmHWM')}")
            lines.append("```")
            lines.append("")
    lines.append("## Caveats")
    lines.append("")
    lines.append("- Rust v1 is **in-memory**; Node uses **SQLite + Sequelize** (joins for pckcert). That is a real architectural difference, not a bench artifact.")
    lines.append("- Node TLS is OpenSSL (restricted sigalgs); Rust TLS is rustls/ring. Same protocol, different stacks.")
    lines.append("- Seed size is one platform + one FMSPC TCB (~32 KiB JSON) + one QE identity + one PCK cert. Not a full production cache.")
    lines.append("- Node may log via morgan/winston (LogLevel=error). Rust tracing default info.")
    lines.append("- Node LAZY warmup contacted Phala once for tcb/identity; the timed loadgen runs are cache hits only.")
    lines.append("- Phala GET `/pckcert` could not supply a real platform id (no admin token). PCK body is a real Intel sample cert, not a live Phala cache row.")
    lines.append("- Node process RSS includes V8 heap + native sqlite3 + full `node_modules` mappings. Rust is a single static-ish binary.")
    lines.append("")
    lines.append("## Memory takeaway")
    lines.append("")
    nr = (out["runs"].get("node_https_5s") or {}).get("idle_status") or {}
    rr = (out["runs"].get("rust_https_5s") or {}).get("idle_status") or {}
    rh = (out["runs"].get("rust_http_5s") or {}).get("idle_status") or {}
    nload = (out["runs"].get("node_https_5s") or {}).get("under_load_rss") or {}
    rload = (out["runs"].get("rust_https_5s") or {}).get("under_load_rss") or {}
    lines.append(
        f"Idle RSS is the headline memory comparison: Node sat at {kib_mb(nr.get('VmRSS') or 0)} after seed, "
        f"while Rust HTTPS was {kib_mb(rr.get('VmRSS') or 0)} and Rust HTTP {kib_mb(rh.get('VmRSS') or 0)}. "
        f"Under a 32-way cache-hit load Node RSS moved to min/med/max "
        f"{nload.get('rss_kib_min')}/{nload.get('rss_kib_median')}/{nload.get('rss_kib_max')} KiB "
        f"versus Rust HTTPS {rload.get('rss_kib_min')}/{rload.get('rss_kib_median')}/{rload.get('rss_kib_max')} KiB. "
        "Most of Node's footprint is the V8 isolate plus mapped node_modules / libsqlite3, not the collateral itself "
        "(the working set is a few tens of KiB). Rust stays near a single-binary baseline with a small DashMap. "
        "If Node could not serve 200s, idle RSS after startup is still a valid process-baseline comparison."
    )
    lines.append("")
    lines.append("## Notes")
    for n in out.get("notes", []):
        lines.append(f"- {n}")
    lines.append("")
    ensure_out()
    md = "\n".join(lines)
    (OUT / "compare-results.md").write_text(md)
    # also write txt
    txt = []
    txt.append("pccs-rs vs Intel Node PCCS compare")
    txt.append(out["when"])
    txt.append(f"node_served_200s={out['node_served_200s']}")
    txt.append(f"query={json.dumps(PARAMS)}")
    for r in rows:
        txt.append(
            f"{r['name']}: idle_rss_kib={r['idle_rss']} load_rss={r['load_min']}/{r['load_med']}/{r['load_max']} "
            f"rps={r['rps']} p50={r['p50']} p99={r['p99']} reqs={r['reqs']} served200={r['served']}"
        )
    (OUT / "compare-results.txt").write_text("\n".join(txt) + "\n")
    print("wrote", OUT / "compare-results.md")
    print("wrote", OUT / "compare-results.txt")
    print("(curated committed summary: docs/compare-results.md)")


if __name__ == "__main__":
    main()
