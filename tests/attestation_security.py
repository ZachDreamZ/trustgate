#!/usr/bin/env python3
"""Focused sign/verify integrity and malformed-signature regression tests."""

import argparse
import json
import os
import subprocess
import tempfile


def run(tg, *argv, cwd):
    return subprocess.run([tg, *argv], cwd=cwd, capture_output=True, text=True, timeout=60)


def require(cond, message):
    if not cond:
        raise AssertionError(message)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tg", required=True)
    args = ap.parse_args()
    tg = os.path.abspath(args.tg)

    with tempfile.TemporaryDirectory(prefix="tg-attest-sec-") as tmp:
        data = os.path.join(tmp, "data.txt")
        with open(data, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("trusted bytes\n")

        p = run(tg, "sign", "--gen-key", "key.hex", cwd=tmp)
        require(p.returncode == 0, f"key generation failed: {p.stderr}")
        p = run(tg, "sign", "--in", "data.txt", "--sig", "data.sig", "--key-file", "key.hex", cwd=tmp)
        require(p.returncode == 0, f"sign failed: {p.stderr}")
        p = run(tg, "verify", "--in", "data.txt", "--sig", "data.sig", "--key-file", "key.hex", cwd=tmp)
        require(p.returncode == 0, f"baseline verify failed: {p.stdout} {p.stderr}")

        original = json.load(open(os.path.join(tmp, "data.sig"), encoding="utf-8"))

        bad = dict(original)
        bad["algorithm"] = "none"
        json.dump(bad, open(os.path.join(tmp, "bad-alg.sig"), "w", encoding="utf-8"))
        p = run(tg, "verify", "--in", "data.txt", "--sig", "bad-alg.sig", "--key-file", "key.hex", cwd=tmp)
        require(p.returncode == 2, f"unsupported algorithm accepted: {p.returncode}")

        bad = dict(original)
        bad["hmac"] = "zz" * 32
        json.dump(bad, open(os.path.join(tmp, "bad-hex.sig"), "w", encoding="utf-8"))
        p = run(tg, "verify", "--in", "data.txt", "--sig", "bad-hex.sig", "--key-file", "key.hex", cwd=tmp)
        require(p.returncode == 2, f"malformed HMAC accepted: {p.returncode}")

        bad = dict(original)
        bad["hmac"] = "00" * 32
        json.dump(bad, open(os.path.join(tmp, "bad-mac.sig"), "w", encoding="utf-8"))
        p = run(tg, "verify", "--in", "data.txt", "--sig", "bad-mac.sig", "--key-file", "key.hex", cwd=tmp)
        require(p.returncode == 2, f"wrong HMAC accepted: {p.returncode}")

        with open(data, "a", encoding="utf-8") as fh:
            fh.write("tamper\n")
        p = run(tg, "verify", "--in", "data.txt", "--sig", "data.sig", "--key-file", "key.hex", cwd=tmp)
        require(p.returncode == 2, f"tampered file accepted: {p.returncode}")

        with open(os.path.join(tmp, "garbage.sig"), "w", encoding="utf-8") as fh:
            fh.write("not-json")
        p = run(tg, "verify", "--in", "data.txt", "--sig", "garbage.sig", "--key-file", "key.hex", cwd=tmp)
        require(p.returncode == 1, f"garbage signature not treated as input error: {p.returncode}")

    print("PASS attestation security suite")


if __name__ == "__main__":
    main()
