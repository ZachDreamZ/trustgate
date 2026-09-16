#!/usr/bin/env python3
"""Focused regression tests for fingerprint format v2 and SHA-256 integrity."""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile


def run(tg, *argv, cwd):
    return subprocess.run(
        [tg, *argv], cwd=cwd, capture_output=True, text=True, timeout=60
    )


def require(cond, message):
    if not cond:
        raise AssertionError(message)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tg", required=True)
    args = ap.parse_args()
    tg = os.path.abspath(args.tg)
    require(os.path.isfile(tg), f"tg binary missing: {tg}")

    with tempfile.TemporaryDirectory(prefix="tg-fp-crypto-") as tmp:
        repo = os.path.join(tmp, "repo")
        os.makedirs(repo)
        alpha = os.path.join(repo, "alpha.txt")
        with open(alpha, "wb") as fh:
            fh.write(b"abc")

        p = run(
            tg, "fingerprint", "--path", repo, "--out", "fp1.json", "--no-probe",
            cwd=tmp,
        )
        require(p.returncode == 0, f"first fingerprint failed: {p.stderr}")
        fp1 = json.load(open(os.path.join(tmp, "fp1.json"), encoding="utf-8"))

        require(fp1.get("version") == 2, f"unexpected version: {fp1.get('version')}")
        require(
            fp1.get("hash_algorithm") == "sha256",
            f"unexpected algorithm: {fp1.get('hash_algorithm')}",
        )
        fid = fp1.get("id", "")
        require(len(fid) == 64, f"fingerprint id is not SHA-256 length: {fid}")
        int(fid, 16)

        entries = {entry["path"]: entry for entry in fp1.get("files", [])}
        require("alpha.txt" in entries, f"alpha.txt missing from fingerprint: {entries}")
        expected = hashlib.sha256(b"abc").hexdigest()
        require(
            entries["alpha.txt"].get("hash") == expected,
            "file hash does not match the FIPS SHA-256 'abc' test vector",
        )

        # Cross-run determinism: metadata timestamps are not part of the ID.
        p = run(
            tg, "fingerprint", "--path", repo, "--out", "fp2.json", "--no-probe",
            cwd=tmp,
        )
        require(p.returncode == 0, f"second fingerprint failed: {p.stderr}")
        fp2 = json.load(open(os.path.join(tmp, "fp2.json"), encoding="utf-8"))
        require(fp1["id"] == fp2["id"], f"IDs differ: {fp1['id']} vs {fp2['id']}")

        cache_path = os.path.join(repo, ".trustgate", "fp-cache.json")
        cache = json.load(open(cache_path, encoding="utf-8"))
        require(cache.get("version") == 2, f"cache version: {cache.get('version')}")
        require(cache.get("algo") == "sha256-1", f"cache algo: {cache.get('algo')}")
        cached_hash = cache.get("entries", {}).get("alpha.txt", {}).get("hash", "")
        require(cached_hash == expected, f"cache digest mismatch: {cached_hash}")

        with open(alpha, "ab") as fh:
            fh.write(b"!")
        p = run(
            tg, "fingerprint", "--path", repo, "--out", "fp3.json", "--no-probe",
            cwd=tmp,
        )
        require(p.returncode == 0, f"drift fingerprint failed: {p.stderr}")
        fp3 = json.load(open(os.path.join(tmp, "fp3.json"), encoding="utf-8"))
        require(fp3["id"] != fp1["id"], "content drift did not change fingerprint ID")

        # v1 used 16-hex FNV-1a-64 IDs/hashes and had no version marker.
        legacy = {
            "id": "0123456789abcdef",
            "os": "linux",
            "created": "2026-01-01T00:00:00Z",
            "files": [
                {"path": "alpha.txt", "size": 3, "hash": "0123456789abcdef"}
            ],
            "toolchain": {},
            "env": {},
        }
        with open(os.path.join(tmp, "legacy.json"), "w", encoding="utf-8") as fh:
            json.dump(legacy, fh)
        p = run(
            tg, "fingerprint", "--compare", "legacy.json", "fp1.json",
            cwd=tmp,
        )
        require(p.returncode == 1, f"legacy fingerprint was not rejected: {p.returncode}")
        require(
            "legacy fingerprint format v1" in p.stderr.lower(),
            f"legacy rejection was not explicit: {p.stderr}",
        )

    print("PASS fingerprint SHA-256 v2 regression suite")


if __name__ == "__main__":
    main()
