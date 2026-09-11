#!/usr/bin/env python3
"""Benchmarks for tg: fingerprint throughput + gate latency.

Results are printed as text (see BENCHMARKS.md for the recorded table).
Usage: python bench/bench.py --tg /path/to/tg[.exe] [--work DIR]
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

TG = None


def run(*argv, cwd):
    t0 = time.perf_counter()
    p = subprocess.run([TG, *argv], cwd=cwd, capture_output=True, text=True, timeout=300)
    dt = time.perf_counter() - t0
    return p, dt


def bench_fingerprint(root, nfiles, size_each):
    d = os.path.join(root, f"fp-{nfiles}")
    os.makedirs(os.path.join(d, "src"))
    payload = ("int f() { return 42; }\n// " + "x" * 64 + "\n") * 8
    while len(payload) < size_each:
        payload += payload
    payload = payload[:size_each]
    for i in range(nfiles):
        with open(os.path.join(d, "src", f"f{i:05d}.cpp"), "w") as fh:
            fh.write(f"// file {i}\n" + payload)
    total_mb = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(d) for f in fs) / 1e6
    p, dt = run("fingerprint", "--path", d, "--out", os.path.join(d, "repro.json"), cwd=root)
    assert p.returncode == 0, p.stderr
    # Second run (warm cache) for stability + timing.
    p2, dt2 = run("fingerprint", "--path", d, "--out", os.path.join(d, "repro2.json"), cwd=root)
    assert p2.returncode == 0, p2.stderr
    fid = json.load(open(os.path.join(d, "repro.json")))["id"]
    fid2 = json.load(open(os.path.join(d, "repro2.json")))["id"]
    assert fid == fid2, "fingerprint unstable!"
    print(f"fingerprint n={nfiles} ({total_mb:.1f} MB): cold {dt*1000:.0f} ms, warm {dt2*1000:.0f} ms, id={fid}")
    return dt


def bench_gate(root, nclaims):
    d = os.path.join(root, f"gate-{nclaims}")
    os.makedirs(os.path.join(d, "src"))
    cases = []
    claims = []
    for i in range(nclaims):
        with open(os.path.join(d, "src", f"m{i:04d}.cpp"), "w") as fh:
            fh.write("int g() { return 1; }\n" * 20)
        tid = f"S.T{i:04d}"
        cases.append(f'<testcase classname="S" name="T{i:04d}" time="0.01"/>')
        claims.append({"id": f"C{i}", "text": f"change {i}",
                       "files": [f"src/m{i:04d}.cpp:1-10"], "tests": [tid]})
    with open(os.path.join(d, "results.xml"), "w") as fh:
        fh.write('<?xml version="1.0"?><testsuites><testsuite name="s" tests="%d">%s</testsuite></testsuites>'
                 % (nclaims, "".join(cases)))
    with open(os.path.join(d, "claims.json"), "w") as fh:
        json.dump({"claims": claims}, fh)
    p, dt = run("gate", "--claims", "claims.json", "--junit", "results.xml",
                "--repo", ".", "--out", "verdict.json", cwd=d)
    assert p.returncode == 0, p.stdout + p.stderr
    print(f"gate n={nclaims} claims+tests: {dt*1000:.0f} ms ({dt*1000/max(nclaims,1):.2f} ms/claim)")
    return dt


def main():
    global TG
    ap = argparse.ArgumentParser()
    ap.add_argument("--tg", required=True)
    ap.add_argument("--work", default=None)
    a = ap.parse_args()
    TG = a.tg
    root = a.work or tempfile.mkdtemp(prefix="tg-bench-")
    os.makedirs(root, exist_ok=True)
    print(f"tg: {TG}")
    print(f"work: {root}")
    bench_fingerprint(root, 46, 1500)   # small sanity scale
    bench_fingerprint(root, 5000, 2048)  # plan target scale
    bench_gate(root, 200)
    bench_gate(root, 2000)
    print("BENCH_DONE")


if __name__ == "__main__":
    sys.exit(main())
