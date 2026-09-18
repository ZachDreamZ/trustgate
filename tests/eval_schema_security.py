#!/usr/bin/env python3
"""Focused fail-closed tests for EvalOps scenario parsing and assertions."""

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


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(data)


def expect_load_failure(tg, root, payload, label):
    cases = os.path.join(root, label)
    os.makedirs(cases)
    if isinstance(payload, str):
        write(os.path.join(cases, "case.json"), payload)
    else:
        write(os.path.join(cases, "case.json"), json.dumps(payload))
    p = run(tg, "eval", "--dir", cases, "--repo", root, "--out", os.path.join(root, f"{label}.json"), cwd=root)
    require(p.returncode != 0, f"{label} unexpectedly passed: {p.stdout} {p.stderr}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tg", required=True)
    args = ap.parse_args()
    tg = os.path.abspath(args.tg)

    with tempfile.TemporaryDirectory(prefix="tg-eval-sec-") as tmp:
        expect_load_failure(tg, tmp, "{broken", "invalid-json")
        expect_load_failure(tg, tmp, {"name": "empty", "asserts": []}, "empty-asserts")
        expect_load_failure(
            tg, tmp,
            {"name": "unknown", "asserts": [{"type": "not-a-real-assert"}]},
            "unknown-assert",
        )
        expect_load_failure(
            tg, tmp,
            {"name": "bad-max", "asserts": [{"type": "max_ms", "value": 0}]},
            "bad-max-ms",
        )
        expect_load_failure(
            tg, tmp,
            {"name": "missing-pattern", "asserts": [{"type": "match"}]},
            "missing-pattern",
        )

        # Runtime assertion errors are scenario failures, not crashes or silent passes.
        cases = os.path.join(tmp, "runtime")
        os.makedirs(cases)
        write(os.path.join(cases, "bad-regex.json"), json.dumps({
            "name": "bad-regex",
            "run": f'"{tg}" --version',
            "asserts": [{"type": "match", "pattern": "[", "regex": True}],
        }))
        p = run(tg, "eval", "--dir", cases, "--repo", tmp, "--out", "runtime.json", cwd=tmp)
        require(p.returncode == 2, f"bad regex did not fail scenario: {p.returncode} {p.stderr}")
        report = json.load(open(os.path.join(tmp, "runtime.json"), encoding="utf-8"))
        result = report.get("results", [{}])[0]
        require(result.get("passed") is False, f"bad regex reported pass: {result}")

    print("PASS EvalOps schema security suite")


if __name__ == "__main__":
    main()
