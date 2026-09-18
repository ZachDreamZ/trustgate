#!/usr/bin/env python3
"""Adversarial gate tests: malformed inputs, repo containment, and large files."""

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


def gate(tg, repo, claims="claims.json", policy="policy.json", *extra):
    return run(
        tg, "gate", "--claims", claims, "--policy", policy,
        "--repo", ".", "--out", "verdict.json", *extra, cwd=repo,
    )


def verdict(repo):
    with open(os.path.join(repo, "verdict.json"), encoding="utf-8") as fh:
        return json.load(fh)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tg", required=True)
    args = ap.parse_args()
    tg = os.path.abspath(args.tg)

    with tempfile.TemporaryDirectory(prefix="tg-gate-sec-") as tmp:
        repo = os.path.join(tmp, "repo")
        os.makedirs(repo)
        write(os.path.join(repo, "inside.txt"), "one\ntwo\n")
        write(os.path.join(tmp, "secret.txt"), "must stay outside\n")
        policy = {
            "require_file_citation": True,
            "require_test_citation": False,
            "require_artifact_citation": False,
            "quarantine_allow": True,
        }
        write(os.path.join(repo, "policy.json"), json.dumps(policy))

        # Malformed claims and policy must fail closed, never crash or PASS.
        write(os.path.join(repo, "claims.json"), "{not-json")
        p = gate(tg, repo)
        require(p.returncode != 0, f"malformed claims passed: {p.stdout} {p.stderr}")

        write(os.path.join(repo, "claims.json"), json.dumps({
            "claims": [{"id": "C", "text": "x", "files": ["inside.txt"]}]
        }))
        write(os.path.join(repo, "bad-policy.json"), "[]")
        p = gate(tg, repo, "claims.json", "bad-policy.json")
        require(p.returncode != 0, f"malformed policy passed: {p.stdout} {p.stderr}")

        # Parent traversal and absolute citations must not escape --repo.
        write(os.path.join(repo, "claims.json"), json.dumps({
            "claims": [{"id": "T1", "text": "escape", "files": ["../secret.txt"]}]
        }))
        p = gate(tg, repo)
        require(p.returncode == 2, f"parent traversal not denied: {p.returncode} {p.stdout}")
        rules = {f.get("rule") for f in verdict(repo).get("findings", [])}
        require("outside-repo" in rules, f"missing outside-repo finding: {rules}")

        write(os.path.join(repo, "claims.json"), json.dumps({
            "claims": [{"id": "T2", "text": "absolute", "files": [os.path.abspath(os.path.join(tmp, "secret.txt"))]}]
        }))
        p = gate(tg, repo)
        require(p.returncode == 2, f"absolute escape not denied: {p.returncode}")
        rules = {f.get("rule") for f in verdict(repo).get("findings", [])}
        require("outside-repo" in rules, f"absolute path finding missing: {rules}")

        # Symlinks that resolve outside the repo are denied where symlinks are available.
        link = os.path.join(repo, "escape-link.txt")
        try:
            os.symlink(os.path.join(tmp, "secret.txt"), link)
        except (OSError, NotImplementedError):
            link = None
        if link:
            write(os.path.join(repo, "claims.json"), json.dumps({
                "claims": [{"id": "T3", "text": "symlink", "files": ["escape-link.txt"]}]
            }))
            p = gate(tg, repo)
            require(p.returncode == 2, f"symlink escape not denied: {p.returncode}")
            rules = {f.get("rule") for f in verdict(repo).get("findings", [])}
            require("outside-repo" in rules, f"symlink finding missing: {rules}")

        # Range checks remain fail-closed.
        write(os.path.join(repo, "claims.json"), json.dumps({
            "claims": [{"id": "R", "text": "range", "files": ["inside.txt:1-999"]}]
        }))
        p = gate(tg, repo)
        require(p.returncode == 2, f"oversized line range not denied: {p.returncode}")
        rules = {f.get("rule") for f in verdict(repo).get("findings", [])}
        require("bad-line-range" in rules, f"bad-line-range finding missing: {rules}")

        # Malformed JUnit/quarantine evidence must never turn a failing test into proof.
        write(os.path.join(repo, "claims.json"), json.dumps({
            "claims": [{"id": "J", "text": "test", "files": ["inside.txt"], "tests": ["S.x"]}]
        }))
        test_policy = dict(policy)
        test_policy["require_test_citation"] = True
        write(os.path.join(repo, "test-policy.json"), json.dumps(test_policy))
        write(os.path.join(repo, "bad.xml"), "<testsuites><broken")
        write(os.path.join(repo, "bad-quarantine.yml"), "not: [valid")
        p = run(
            tg, "gate", "--claims", "claims.json", "--policy", "test-policy.json",
            "--repo", ".", "--junit", "bad.xml", "--quarantine", "bad-quarantine.yml",
            "--out", "verdict.json", cwd=repo,
        )
        require(p.returncode != 0, f"malformed evidence passed: {p.stdout} {p.stderr}")

        # Large-file hashing should remain bounded and deterministic.
        large = os.path.join(repo, "large.bin")
        with open(large, "wb") as fh:
            fh.write((b"TrustGate-large-fixture\n" * 100000))
        p = run(tg, "fingerprint", "--path", repo, "--out", "large-fp.json", "--no-probe", cwd=tmp)
        require(p.returncode == 0, f"large fingerprint failed: {p.stderr}")
        fp = json.load(open(os.path.join(tmp, "large-fp.json"), encoding="utf-8"))
        entry = next((x for x in fp.get("files", []) if x.get("path") == "large.bin"), None)
        require(entry is not None and len(entry.get("hash", "")) == 64, f"large file hash missing: {entry}")

    print("PASS gate security regression suite")


if __name__ == "__main__":
    main()
