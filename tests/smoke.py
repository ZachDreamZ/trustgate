#!/usr/bin/env python3
"""End-to-end smoke test for the `tg` binary.

Builds a throwaway fixture repo in a tmpdir and exercises:
  gate DENY / lenient / PASS / quarantine-allow / SARIF output,
  fingerprint stability + drift detection,
  flake history scoring -> quarantine.yml,
  init (including --force guard).

Usage: python tests/smoke.py --tg /path/to/tg[.exe]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print(f"PASS {name}")
    else:
        msg = f"FAIL {name}" + (f": {detail}" if detail else "")
        print(msg)
        FAILURES.append(msg)


def run(tg, *argv, cwd):
    proc = subprocess.run(
        [tg, *argv], cwd=cwd, capture_output=True, text=True, timeout=60
    )
    return proc


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


# Fixed mtime for fixture files: hash-cache assertions must not depend on
# wall-clock timestamp behavior of the runner's filesystem (some CI /tmp
# mounts have coarse or quirky timestamp granularity). Drift detection is
# content-based, so pinning mtimes is safe.
PINNED_NS = 1700000000 * 10**9


def pin_mtimes(path):
    for dp, _, fs in os.walk(path):
        for f in fs:
            p = os.path.join(dp, f)
            os.utime(p, ns=(PINNED_NS, PINNED_NS))


JUNIT_BASE = """<?xml version="1.0"?>
<testsuites>
  <testsuite name="auth" tests="2">
    <testcase classname="AuthTest" name="RefreshToken" time="0.12"/>
    <testcase classname="AuthTest" name="Logout" time="0.05">
      <failure message="timeout">stack here</failure>
    </testcase>
  </testsuite>
</testsuites>
"""

JUNIT_ALLPASS = """<?xml version="1.0"?>
<testsuites>
  <testsuite name="auth" tests="2">
    <testcase classname="AuthTest" name="RefreshToken" time="0.10"/>
    <testcase classname="AuthTest" name="Logout" time="0.04"/>
  </testsuite>
</testsuites>
"""


def check_junit_resolution(tg, root):
    """Exercise citation resolution through the real gate, including shard merges."""
    repo = os.path.join(root, "junit-resolution")
    os.makedirs(repo)
    write(os.path.join(repo, "policy.json"), json.dumps({
        "require_file_citation": False, "require_test_citation": True,
        "require_artifact_citation": False, "quarantine_allow": True,
    }))

    def testcase(name="Run", classname="", status="P"):
        child = {"P": "", "F": "<failure/>", "S": "<skipped/>"}[status]
        return f'<testcase classname="{classname}" name="{name}">{child}</testcase>'

    def suite(name, *cases):
        return f"<testsuite name='{name}'>" + "".join(cases) + "</testsuite>"

    def gate_case(label, reports, ref, rule=None, extra=(), reverse=False,
                  observations=None, quarantined_used=None):
        write(os.path.join(repo, "claims.json"), json.dumps({
            "claims": [{"id": "J", "text": "JUnit citation", "tests": [ref]}],
        }))
        paths = []
        for i, xml in enumerate(reports):
            path = f"report-{i}.xml"
            paths.append(path)
            write(os.path.join(repo, path), xml)
        if reverse:
            paths.reverse()
        junit_args = [arg for path in paths for arg in ("--junit", path)]
        p = run(tg, "gate", "--claims", "claims.json", "--policy", "policy.json",
                "--repo", ".", "--out", "verdict.json", "--sarif", "results.sarif",
                *junit_args, *extra, cwd=repo)
        data = json.load(open(os.path.join(repo, "verdict.json"), encoding="utf-8"))
        expected_warning = rule == "quarantined-failure" or "--lenient" in extra
        expected_exit = 0 if rule is None or expected_warning else 2
        expected_verdict = ("PASS_WITH_WARNINGS" if expected_warning else
                            "PASS" if rule is None else "DENY")
        findings = data.get("findings", [])
        expected_rules = [] if rule is None else [rule]
        check(label, p.returncode == expected_exit and
              data.get("verdict") == expected_verdict and
              [f.get("rule") for f in findings] == expected_rules,
              f"exit={p.returncode}, verdict={data}, stderr={p.stderr}")
        if observations is None:
            observations = sum(xml.count("<testcase ") for xml in reports)
        check(label + " observation count", data.get("stats", {}).get("junit_tests") ==
              observations, str(data))
        if quarantined_used is not None:
            check(label + " quarantine identity", data.get("stats", {}).get("quarantined_used") ==
                  quarantined_used, str(data))
        if rule:
            severity = "warning" if expected_warning else "error"
            check(label + " finding severity", len(findings) == 1 and
                  findings[0].get("severity") == severity)
            sarif = json.load(open(os.path.join(repo, "results.sarif"), encoding="utf-8"))
            results = sarif["runs"][0]["results"]
            check(label + " SARIF rule", len(results) == 1 and
                  results[0]["ruleId"] == "trustgate/" + rule)
        return tuple(open(os.path.join(repo, path), "rb").read()
                     for path in ("verdict.json", "results.sarif"))

    status_rules = {"P": None, "F": "failed-test", "S": "skipped-test"}
    for status, rule in status_rules.items():
        for classname in ("", "Auth"):
            xml = suite("single", testcase(classname=classname, status=status))
            gate_case(f"unique bare {classname or 'no class'} {status}", [xml], "Run", rule)
            if classname:
                gate_case(f"qualified class {status}", [xml], "Auth.Run", rule)

    # Bare duplicates are ambiguous even if every observation passed. Qualified
    # references still resolve each class/suite to its own P/F/S outcome.
    for left, right in (("P", "P"), ("P", "F"), ("P", "S"), ("F", "S")):
        classes = suite("unit", testcase(classname="First", status=left),
                        testcase(classname="Second", status=right))
        gate_case(f"duplicate classes {left}{right}", [classes], "Run", "ambiguous-test")
        gate_case(f"first class {left}{right}", [classes], "First.Run", status_rules[left])
        gate_case(f"second class {left}{right}", [classes], "Second.Run", status_rules[right])
        suites = "<testsuites>" + suite("one", testcase(status=left)) + \
                 suite("two", testcase(status=right)) + "</testsuites>"
        gate_case(f"duplicate suites {left}{right}", [suites], "Run", "ambiguous-test")
        gate_case(f"first suite {left}{right}", [suites], "one.Run", status_rules[left])
        gate_case(f"second suite {left}{right}", [suites], "two.Run", status_rules[right])

    across_suites = [suite("one", testcase(classname="Auth")),
                     suite("two", testcase(classname="Auth", status="S"))]
    gate_case("duplicate qualified id across reports", across_suites,
              "Auth.Run", "ambiguous-test")
    gate_case("suite and class passing", across_suites, "one.Auth.Run")
    gate_case("suite and class skipped", across_suites, "two.Auth.Run", "skipped-test")
    nested = [suite("outer", suite("empty"), suite("inner", testcase(classname="Auth")),
                    suite("sibling", testcase(classname="Auth", status="F")))]
    gate_case("nested suite passing", nested, "outer.inner.Auth.Run")
    gate_case("nested sibling failing", nested, "outer.sibling.Auth.Run", "failed-test")

    # The same logical test repeated in shards remains one candidate, with
    # F > S > P independently of file order or citation spelling.
    for statuses, rule in (("PP", None), ("PS", "skipped-test"),
                           ("PF", "failed-test"), ("SF", "failed-test")):
        reports = [suite("unit", testcase(classname="Auth", status=s)) for s in statuses]
        for ref in ("Run", "Auth.Run", "unit.Auth.Run"):
            label = f"overlapping shards {statuses} {ref}"
            first = gate_case(label, reports, ref, rule)
            second = gate_case(label + " reversed", reports, ref, rule, reverse=True)
            check(label + " deterministic", first == second)

    aliases = [suite("one", testcase(classname="Auth")),
               suite("two", testcase(name="Auth.Run"))]
    gate_case("bare alias collides with qualified id", aliases, "Auth.Run", "ambiguous-test")
    gate_case("qualified collision first suite", aliases, "one.Auth.Run")
    gate_case("qualified collision second suite", aliases, "two.Auth.Run")
    dotted = [suite("dots", testcase(name="part.Run", classname="Auth"),
                    testcase(name="Run", classname="Auth.part", status="F"))]
    gate_case("dotted qualified collision", dotted, "Auth.part.Run", "ambiguous-test")
    gate_case("unique dotted bare name", dotted, "part.Run")
    gate_case("other dotted identity", dotted, "Run", "failed-test")
    gate_case("unknown test unchanged", aliases, "Absent", "unknown-test")

    write(os.path.join(repo, "quarantine.yml"),
          "version: 1\nquarantined:\n  - id: Run\n    flake_rate: 0.5\n"
          "  - id: First.Run\n    flake_rate: 0.5\n")
    quarantined = [suite("unit", testcase(classname="First", status="F"),
                         testcase(classname="Second"))]
    first = gate_case("quarantine cannot resolve ambiguity", quarantined, "Run", "ambiguous-test")
    gate_case("qualified quarantine unchanged", quarantined, "First.Run", "quarantined-failure")
    gate_case("lenient ambiguity warns", quarantined, "Run", "ambiguous-test", extra=("--lenient",))
    swapped = [suite("unit", testcase(classname="Second"),
                     testcase(classname="First", status="F"))]
    second = gate_case("testcase order ambiguity", swapped, "Run", "ambiguous-test")
    check("ambiguous verdict deterministic", first == second)

    # Inert XML text cannot change a test's suite or create observations.
    inert_regions = (
        "<!-- diagnostic > </testsuite><testsuite name='other'> -->",
        "<![CDATA[diagnostic > </testsuite><testsuite name='other'>]]>",
        "<?diagnostic text > </testsuite><testsuite name='other'> ?>",
    )
    for i, inert in enumerate(inert_regions):
        for statuses in ("PF", "FP"):
            xml = [suite("unit", testcase(classname="Auth", status=statuses[0]),
                         inert, testcase(classname="Auth", status=statuses[1]))]
            for ref in ("Run", "Auth.Run", "unit.Auth.Run"):
                gate_case(f"inert suite text {i} {statuses} {ref}", xml, ref, "failed-test")
        fake = testcase(name="NotATest")
        wrapped = ("<!-- > " + fake + " -->", "<![CDATA[ > " + fake + "]]>",
                   "<?diagnostic > " + fake + " ?>")[i]
        xml = [suite("unit", wrapped, testcase(classname="Auth"))]
        gate_case(f"inert testcase text {i}", xml, "unit.Auth.Run", observations=1)
        gate_case(f"inert testcase absent {i}", xml, "NotATest", "unknown-test", observations=1)
        inner = ("<!-- > </testcase> <failure/> -->", "<![CDATA[ > </testcase> <failure/> ]]>",
                 "<?diagnostic > </testcase> <failure/> ?>")[i]
        xml = [suite("unit", '<testcase classname="Auth" name="Run">' + inner + '</testcase>')]
        gate_case(f"inert testcase children {i}", xml, "unit.Auth.Run")

    quoted = [suite("unit>detail", testcase(name="Run>detail", classname="Auth>detail", status="F"))]
    gate_case("quoted tag delimiters", quoted, "unit>detail.Auth>detail.Run>detail", "failed-test")

    # XML serialization must not change the identity of repeated observations.
    equivalent_names = (
        ("unit>detail", "unit&gt;detail", "unit>detail"),
        ("unit&gt;detail", "unit&#62;detail", "unit>detail"),
        ("unit&#62;detail", "unit&#x3e;detail", "unit>detail"),
        ("u&amp;n&lt;i&quot;t&apos;", "u&#38;n&#60;i&#34;t&#39;", 'u&n<i"t\''),
        ("caf\u00e9", "caf&#233;", "caf\u00e9"),
        ("\U0001f600", "&#x1F600;", "\U0001f600"),
        ("unit detail", "unit\r\ndetail", "unit detail"),
        ("unit&amp;gt;detail", "unit&#38;gt;detail", "unit&gt;detail"),
    )
    for i, (left, right, decoded) in enumerate(equivalent_names):
        for attr in ("suite", "class", "test"):
            def encoded_case(value, status):
                sn, cn, tn = (value, "Auth", "Run") if attr == "suite" else (
                    ("unit", value, "Run") if attr == "class" else ("unit", "Auth", value))
                return (f'<testsuite name="{sn}"><testcase classname="{cn}" name="{tn}">'
                        + ("<failure/>" if status == "F" else "") + "</testcase></testsuite>")
            ref = {"suite": f"{decoded}.Auth.Run", "class": f"unit.{decoded}.Run",
                   "test": f"unit.Auth.{decoded}"}[attr]
            reports = [encoded_case(left, "P"), encoded_case(right, "F")]
            first = gate_case(f"XML identity {i} {attr}", reports, ref, "failed-test")
            second = gate_case(f"XML identity {i} {attr} reversed", reports, ref,
                               "failed-test", reverse=True)
            check(f"XML identity {i} {attr} deterministic", first == second)
            gate_case(f"XML identity {i} {attr} passing control", [encoded_case(right, "P")], ref)

    for i, space in enumerate((" ", "\t", "\n", "\r", " \t\r\n ")):
        alternate = (f'<testsuite name{space}={space}\'unit\'>'
                     f'<testcase classname{space}={space}\'Auth\' name{space}={space}\'Run\'>'
                     "<failure/></testcase></testsuite>")
        reports = [suite("unit", testcase(classname="Auth")), alternate]
        for ref in ("Run", "Auth.Run", "unit.Auth.Run"):
            gate_case(f"XML attribute whitespace {i} {ref}", reports, ref, "failed-test")
            gate_case(f"XML attribute whitespace {i} {ref} reversed", reports, ref,
                      "failed-test", reverse=True)

    # Unsupported/malformed attribute values cannot become partial evidence.
    for i, value in enumerate(("&unknown;", "&amp", "&#;", "&#x;", "&#-1;", "&#0;",
                               "&#xD800;", "&#xFFFE;", "&#x110000;",
                               "&#999999999999999999999999;", "unescaped&value")):
        write(os.path.join(repo, "invalid.xml"),
              f'<testsuite name="{value}">' + testcase(classname="Auth") + '</testsuite>')
        p = run(tg, "gate", "--claims", "claims.json", "--policy", "policy.json",
                "--junit", "invalid.xml", "--out", "invalid.json", cwd=repo)
        check(f"invalid XML attribute rejected {i}", p.returncode == 1, p.stdout + p.stderr)

    # Quarantine IDs belong to resolved tests, not the spelling of a citation.
    def quarantine(*ids):
        write(os.path.join(repo, "quarantine.yml"), "version: 1\nquarantined:\n" +
              "".join(f"  - id: {test_id}\n    flake_rate: 0.5\n" for test_id in ids))

    failing = [suite("unit", testcase(classname="Auth", status="F"))]
    quarantine("Run", "unit.Auth.Run")
    for ref in ("Run", "Auth.Run", "unit.Auth.Run"):
        gate_case(f"unrelated quarantine {ref}", failing, ref, "failed-test", quarantined_used=[])
    quarantine("Auth.Run")
    for ref in ("Run", "Auth.Run", "unit.Auth.Run"):
        gate_case(f"resolved quarantine {ref}", failing, ref, "quarantined-failure",
                  quarantined_used=["Auth.Run"])
    quarantine("Run")
    for ref in ("Run", "unit.Run"):
        gate_case(f"classless quarantine {ref}", [suite("unit", testcase(status="F"))], ref,
                  "quarantined-failure", quarantined_used=["Run"])
    quarantine("Auth.Run")
    gate_case("quarantine never allows skipped alias", [suite("unit", testcase(classname="Auth", status="S"))],
              "Run", "skipped-test", quarantined_used=[])
    gate_case("quarantine identity remains ambiguous", across_suites, "Auth.Run", "ambiguous-test",
              quarantined_used=[])
    same_id = [suite("one", testcase(classname="Auth", status="F")),
               suite("two", testcase(classname="Auth"))]
    gate_case("ambiguous canonical quarantine denied", same_id, "one.Auth.Run", "failed-test",
              quarantined_used=[])
    quarantine("Auth.part.Run")
    gate_case("dotted canonical quarantine denied", dotted, "Run", "failed-test", quarantined_used=[])
    quarantine("Run")
    gate_case("lenient unresolved quarantine warns", failing, "Run", "failed-test", extra=("--lenient",),
              quarantined_used=[])
    quarantine("Auth.Run")
    write(os.path.join(repo, "policy.json"), json.dumps({
        "require_file_citation": False, "require_test_citation": True,
        "require_artifact_citation": False, "quarantine_allow": False,
    }))
    gate_case("disabled quarantine denies alias", failing, "Run", "failed-test", quarantined_used=[])

    # Incomplete inert regions must fail as input errors, never use partial proof.
    for ending in ("<!-- unfinished", "<![CDATA[unfinished", "<?diagnostic unfinished"):
        write(os.path.join(repo, "report-0.xml"), suite("unit", testcase(classname="Auth"), ending))
        p = run(tg, "gate", "--claims", "claims.json", "--policy", "policy.json",
                "--junit", "report-0.xml", "--out", "incomplete.json", cwd=repo)
        check("incomplete XML region rejected " + ending, p.returncode == 1, p.stdout + p.stderr)

    # The shared parser also feeds flake history; retain ordinary diagnostics.
    diagnostics = (
        ('<error message="Connection refused"> socket\n unavailable </error>',
         "F", "Connection refused | socket unavailable"),
        ('<error message="earlier"/><failure message="assertion"> expected value </failure>',
         "F", "assertion | expected value"),
        ('<failure message="expected > actual"> detail </failure>',
         "F", "expected > actual | detail"),
        ('<!-- > <failure message="ignored"/> --><error message="actual"/>', "F", "actual"),
        ('<failure message="limit">' + "x" * 400 + '</failure>', "F", "limit | " + "x" * 300),
    )
    for i, (children, status, message) in enumerate(diagnostics):
        write(os.path.join(repo, "diagnostic.xml"), suite("unit",
              '<testcase classname="S" name="Diagnostic">' + children + '</testcase>'))
        p = run(tg, "flake", "--junit", "diagnostic.xml", "--history", "diagnostic-history.jsonl",
                "--out", "diagnostic-quarantine.yml", cwd=repo)
        check(f"failure diagnostic flake {i}", p.returncode == 0, p.stderr)
        history = open(os.path.join(repo, "diagnostic-history.jsonl"), encoding="utf-8").read().splitlines()
        result = json.loads(history[-1])["results"]["S.Diagnostic"]
        # Flake history retains at most 200 characters of the parser's excerpt.
        check(f"failure diagnostic preserved {i}", result["s"] == status and result["m"] == message[:200],
              str(result))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tg", required=True, help="path to tg binary")
    args = ap.parse_args()
    tg = args.tg
    check("binary exists", os.path.isfile(tg), tg)
    tg = os.path.abspath(tg)  # run-commands below execute with various cwds

    tmp = tempfile.mkdtemp(prefix="tg-smoke-")
    repo = os.path.join(tmp, "repo")
    os.makedirs(os.path.join(repo, "src"))
    os.makedirs(os.path.join(repo, "logs"))

    auth_cpp = "".join(f"// line {i}\nint f{i}() {{ return {i}; }}\n" for i in range(1, 16))
    write(os.path.join(repo, "src", "auth.cpp"), auth_cpp)
    write(os.path.join(repo, "src", "main.cpp"), "int main() { return 0; }\n")
    write(os.path.join(repo, "logs", "test.log"), "tests ran\n")
    write(os.path.join(repo, "results.xml"), JUNIT_BASE)
    pin_mtimes(os.path.join(repo, "src"))

    claims = {
        "claims": [
            {
                "id": "C1",
                "text": "Fix NPE in auth refresh",
                "files": ["src/auth.cpp:1-10"],
                "tests": ["AuthTest.RefreshToken"],
                "artifacts": ["logs/test.log"],
            },
            {"id": "C2", "text": "Trust me, it works"},
        ]
    }
    write(os.path.join(repo, "claims.json"), json.dumps(claims))

    # --- 1. DENY on uncited claim ---
    p = run(
        tg, "gate", "--claims", "claims.json", "--junit", "results.xml",
        "--repo", ".", "--out", "verdict.json", "--sarif", "results.sarif",
        cwd=repo,
    )
    check("gate DENY exit code", p.returncode == 2, f"got {p.returncode}: {p.stderr}")
    try:
        verdict = json.load(open(os.path.join(repo, "verdict.json"), encoding="utf-8"))
    except Exception as ex:  # noqa: BLE001
        verdict = {}
        check("verdict.json parses", False, str(ex))
    check("verdict is DENY", verdict.get("verdict") == "DENY", str(verdict.get("verdict")))
    rules = {(f.get("rule"), f.get("claim")) for f in verdict.get("findings", [])}
    check("uncited-files flagged for C2", ("uncited-files", "C2") in rules, str(rules))
    check("uncited-tests flagged for C2", ("uncited-tests", "C2") in rules, str(rules))

    # --- 2. SARIF output ---
    try:
        sarif = json.load(open(os.path.join(repo, "results.sarif"), encoding="utf-8"))
        sarif_ok = (
            sarif.get("version") == "2.1.0"
            and len(sarif.get("runs", [{}])[0].get("results", [])) > 0
        )
    except Exception as ex:  # noqa: BLE001
        sarif_ok = False
        sarif = {"error": str(ex)}
    check("sarif valid with results", sarif_ok, str(sarif)[:200])

    # --- 3. lenient mode warns instead of denying ---
    p = run(
        tg, "gate", "--claims", "claims.json", "--junit", "results.xml",
        "--repo", ".", "--out", "verdict-lenient.json", "--lenient", cwd=repo,
    )
    check("gate --lenient exit 0", p.returncode == 0, f"got {p.returncode}: {p.stderr}")
    verdict_l = json.load(open(os.path.join(repo, "verdict-lenient.json"), encoding="utf-8"))
    check(
        "lenient verdict warns",
        verdict_l.get("verdict") == "PASS_WITH_WARNINGS",
        str(verdict_l.get("verdict")),
    )

    # --- 4. fully-cited claims PASS ---
    ok_claims = {"claims": [dict(claims["claims"][0])]}
    write(os.path.join(repo, "claims-ok.json"), json.dumps(ok_claims))
    p = run(
        tg, "gate", "--claims", "claims-ok.json", "--junit", "results.xml",
        "--repo", ".", "--out", "verdict-ok.json", cwd=repo,
    )
    check("gate PASS exit 0", p.returncode == 0, f"got {p.returncode}: {p.stdout} {p.stderr}")

    # --- 5. failed test DENY, then quarantine-allow ---
    q_claims = {
        "claims": [
            {
                "id": "C3",
                "text": "Logout change",
                "files": ["src/auth.cpp:1-5"],
                "tests": ["AuthTest.Logout"],
            }
        ]
    }
    write(os.path.join(repo, "claims-q.json"), json.dumps(q_claims))
    p = run(
        tg, "gate", "--claims", "claims-q.json", "--junit", "results.xml",
        "--repo", ".", "--out", "verdict-q.json", cwd=repo,
    )
    check("failed test DENY", p.returncode == 2, f"got {p.returncode}")
    write(
        os.path.join(repo, "quarantine.yml"),
        "version: 1\nquarantined:\n"
        "  - id: AuthTest.Logout\n    flake_rate: 0.5\n    runs: 4\n"
        "    ttl_days: 14\n    reason: \"smoke\"\n",
    )
    p = run(
        tg, "gate", "--claims", "claims-q.json", "--junit", "results.xml",
        "--repo", ".", "--out", "verdict-q2.json",
        "--quarantine", "quarantine.yml", cwd=repo,
    )
    check("quarantined failure warns", p.returncode == 0, f"got {p.returncode}: {p.stdout}")

    check_junit_resolution(tg, tmp)

    # --- 6. fingerprint stability + drift ---
    # Scan only the src/ subtree; outputs live in repo/ root so runs cannot
    # observe their own output files.
    srcdir = os.path.join(repo, "src")
    p = run(tg, "fingerprint", "--path", srcdir, "--out", "repro1.json", cwd=repo)
    check("fingerprint run 1", p.returncode == 0, p.stderr)
    p = run(tg, "fingerprint", "--path", srcdir, "--out", "repro2.json", cwd=repo)
    id1 = json.load(open(os.path.join(repo, "repro1.json"), encoding="utf-8"))["id"]
    id2 = json.load(open(os.path.join(repo, "repro2.json"), encoding="utf-8"))["id"]
    check("fingerprint stable", id1 == id2, f"{id1} vs {id2}")
    with open(os.path.join(srcdir, "auth.cpp"), "a", encoding="utf-8") as fh:
        fh.write("// drift\n")
    pin_mtimes(srcdir)
    p = run(tg, "fingerprint", "--path", srcdir, "--out", "repro3.json", cwd=repo)
    id3 = json.load(open(os.path.join(repo, "repro3.json"), encoding="utf-8"))["id"]
    check("fingerprint changes on drift", id3 != id1, f"{id1} vs {id3}")
    p = run(
        tg, "fingerprint", "--compare", "repro1.json", "repro3.json",
        "--out", "diff.json", cwd=repo,
    )
    check("compare exit 4 on drift", p.returncode == 4, f"got {p.returncode}")
    diff = json.load(open(os.path.join(repo, "diff.json"), encoding="utf-8"))
    check(
        "compare names changed file",
        "auth.cpp" in diff.get("changed", []),
        str(diff),
    )

    # --- 7. flake history -> quarantine with root causes ---
    flake_dir = os.path.join(tmp, "flake")
    os.makedirs(flake_dir)
    PASS = None
    runs = [
        ("run1.xml", {"A": PASS, "B": PASS, "C": PASS}),
        ("run2.xml", {"A": PASS, "B": "Connection refused: localhost:5432",
                      "C": "AssertionError: expected 200 but got 404"}),
        ("run3.xml", {"A": PASS, "B": "Connection refused: localhost:5432", "C": PASS}),
        ("run4.xml", {"A": PASS, "B": PASS, "C": PASS}),
    ]
    for name, specs in runs:
        cases = []
        for tname, res in specs.items():
            if res is None:
                cases.append(f'<testcase classname="S" name="{tname}" time="0.01"/>')
            else:
                cases.append(
                    f'<testcase classname="S" name="{tname}" time="0.01">'
                    f"<failure message=\"{res}\">{res} at test line 1</failure></testcase>"
                )
        write(os.path.join(flake_dir, name),
              '<?xml version="1.0"?><testsuites><testsuite name="s" tests="3">'
              + "".join(cases) + "</testsuite></testsuites>")
        p = run(
            tg, "flake", "--junit", name,
            "--history", "hist.jsonl", "--out", "q.yml", cwd=flake_dir,
        )
        check(f"flake {name} exit 0", p.returncode == 0, p.stderr)
    qtext = open(os.path.join(flake_dir, "q.yml"), encoding="utf-8").read()
    check("flaky B quarantined", "S.B" in qtext, qtext[:400])
    check("B cause is network", "network" in qtext, qtext[:400])
    check("flaky C quarantined", "S.C" in qtext, qtext[:400])
    check("C cause is assertion", "assertion" in qtext, qtext[:400])
    check("stable A not quarantined", "S.A" not in qtext, qtext[:400])

    # --- 8. init + --force guard ---
    initproj = os.path.join(tmp, "initproj")
    os.makedirs(initproj)
    p = run(tg, "init", "--path", ".", cwd=initproj)
    check("init exit 0", p.returncode == 0, p.stderr)
    check(
        "init writes policy",
        os.path.isfile(os.path.join(initproj, ".trustgate", "policy.json")),
    )
    p = run(tg, "init", "--path", ".", cwd=initproj)
    check("init refuses overwrite", p.returncode == 1, f"got {p.returncode}")
    p = run(tg, "init", "--path", ".", "--force", cwd=initproj)
    check("init --force overwrites", p.returncode == 0, p.stderr)

    # --- 9. hash cache: same ID with/without cache, cache file created ---
    # (srcdir was drifted in step 6; id3 is the uncached drifted ID.)
    cache_path = os.path.join(tmp, "fp-cache.json")
    p = run(tg, "fingerprint", "--path", srcdir, "--out", "c1.json",
            "--cache", cache_path, cwd=repo)
    check("fingerprint --cache exit 0", p.returncode == 0, p.stderr)
    check("cache file created", os.path.isfile(cache_path))
    id_c1 = json.load(open(os.path.join(repo, "c1.json"), encoding="utf-8"))["id"]
    check("cache ID matches uncached ID", id_c1 == id3, f"{id_c1} vs {id3}")
    p = run(tg, "fingerprint", "--path", srcdir, "--out", "c2.json",
            "--cache", cache_path, cwd=repo)
    id_c2 = json.load(open(os.path.join(repo, "c2.json"), encoding="utf-8"))["id"]
    check("cached rerun same ID", id_c1 == id_c2, f"{id_c1} vs {id_c2}")
    check("cached rerun reports reuse", "hash cache" in p.stdout, p.stdout[:200])
    p = run(tg, "fingerprint", "--path", srcdir, "--out", "c3.json", "--no-cache", cwd=repo)
    id_c3 = json.load(open(os.path.join(repo, "c3.json"), encoding="utf-8"))["id"]
    check("no-cache same ID", id_c3 == id_c1, f"{id_c3} vs {id_c1}")

    # --- 10. version + unknown command codes ---
    p = run(tg, "--version", cwd=tmp)
    check("version exit 0", p.returncode == 0 and "tg " in p.stdout, p.stdout)
    p = run(tg, "nope", cwd=tmp)
    check("unknown command exit 1", p.returncode == 1, f"got {p.returncode}")
    p = run(tg, "wrap", cwd=tmp)
    check("wrap missing command exit 1", p.returncode == 1, f"got {p.returncode}")
    p = run(tg, "eval", cwd=tmp)
    check("eval missing dir exit 1", p.returncode == 1, f"got {p.returncode}")

    # --- 11. eval: deterministic scenarios ---
    evdir = os.path.join(tmp, "evals")
    os.makedirs(os.path.join(evdir, "cases"))
    write(os.path.join(evdir, "a.txt"), "hello world\n")
    write(os.path.join(evdir, "data.json"), json.dumps({"verdict": "PASS", "n": 3}))
    tgq = f'"{tg}" --version'
    write(os.path.join(evdir, "cases", "pass.json"), json.dumps({
        "name": "pass-all",
        "run": tgq,
        "asserts": [
            {"type": "exit_code", "expected": 0},
            {"type": "match", "pattern": "tg "},
            {"type": "match", "file": "a.txt", "pattern": "world"},
            {"type": "match", "file": "a.txt", "pattern": "zzz", "present": False},
            {"type": "match", "file": "a.txt", "pattern": "h.llo", "regex": True},
            {"type": "file_exists", "path": "data.json"},
            {"type": "json_field", "file": "data.json", "field": "verdict", "equals": "PASS"},
            {"type": "max_ms", "value": 60000},
        ],
    }))
    write(os.path.join(evdir, "cases", "fail.json"), json.dumps({
        "name": "fail-exit",
        "run": tgq,
        "asserts": [{"type": "exit_code", "expected": 7}],
    }))
    p = run(tg, "eval", "--dir", "cases", "--repo", ".", "--out", "r1.json",
            "--history", "h.jsonl", cwd=evdir)
    check("eval mixed exit 2", p.returncode == 2, f"got {p.returncode}: {p.stdout}")
    r1 = json.load(open(os.path.join(evdir, "r1.json"), encoding="utf-8"))
    by_name = {r["name"]: r for r in r1.get("results", [])}
    check("eval pass-all passed", by_name.get("pass-all", {}).get("passed") is True,
          str(by_name.get("pass-all")))
    check("eval fail-exit failed", by_name.get("fail-exit", {}).get("passed") is False,
          str(by_name.get("fail-exit")))
    p = run(tg, "eval", "--dir", "cases", "--repo", ".", "--out", "r2.json",
            "--history", "h.jsonl", "--filter", "pass-all", cwd=evdir)
    check("eval --filter exit 0", p.returncode == 0, f"got {p.returncode}: {p.stdout}")
    p = run(tg, "eval", "--trend", "--history", os.path.join(evdir, "h.jsonl"), cwd=tmp)
    check("eval --trend exit 0", p.returncode == 0, p.stderr)
    check("trend names both evals",
          "pass-all" in p.stdout and "fail-exit" in p.stdout, p.stdout[:300])

    # --- 12. systemic clustering: co-failing pair groups, solo flake does not ---
    cdir = os.path.join(tmp, "cluster")
    os.makedirs(cdir)
    NET = "Connection refused: db:5432"
    TIMED = "Timed out after 30s waiting for lock"
    ASSR = "AssertionError: expected true"
    cruns = [
        ("c1.xml", {"B": NET, "C": NET, "D": PASS}),
        ("c2.xml", {"B": NET, "C": NET, "D": ASSR}),
        ("c3.xml", {"B": NET, "C": NET, "D": PASS}),
        ("c4.xml", {"B": PASS, "C": PASS, "D": TIMED}),
    ]
    for name, specs in cruns:
        cases = []
        for tname, res in specs.items():
            if res is None:
                cases.append(f'<testcase classname="S" name="{tname}" time="0.01"/>')
            else:
                cases.append(
                    f'<testcase classname="S" name="{tname}" time="0.01">'
                    f"<failure message=\"{res}\">{res} here</failure></testcase>"
                )
        write(os.path.join(cdir, name),
              '<?xml version="1.0"?><testsuites><testsuite name="s" tests="3">'
              + "".join(cases) + "</testsuite></testsuites>")
    for name, _ in cruns:
        p = run(tg, "flake", "--junit", name, "--history", "chist.jsonl",
                "--out", "cq.yml", "--clusters-out", "clusters.json", cwd=cdir)
        check(f"cluster {name} exit 0", p.returncode == 0, p.stderr)
    cl = json.load(open(os.path.join(cdir, "clusters.json"), encoding="utf-8"))
    groups = [sorted(g["tests"]) for g in cl.get("clusters", [])]
    check("B+C systemic cluster", ["S.B", "S.C"] in groups, str(groups))
    check("D not clustered", all("S.D" not in g for g in groups), str(groups))
    bc = next(g for g in cl["clusters"] if sorted(g["tests"]) == ["S.B", "S.C"])
    check("cluster cause network", bc.get("cause") == "network", str(bc))

    # --- 13. sign/verify round-trip, RFC vector, tamper matrix ---
    sdir = os.path.join(tmp, "sign")
    os.makedirs(sdir)
    write(os.path.join(sdir, "data.txt"), "important bytes\n")
    import hashlib as _hashlib
    import hmac as _hmac
    import shutil as _shutil
    write(os.path.join(sdir, "rfc.txt"), "Hi There")
    p = run(tg, "sign", "--in", "rfc.txt", "--sig", "rfc.sig",
            "--key", "0b" * 20, cwd=sdir)
    check("sign rfc exit 0", p.returncode == 0, p.stderr)
    sig = json.load(open(os.path.join(sdir, "rfc.sig"), encoding="utf-8"))
    expect = _hmac.new(bytes.fromhex("0b" * 20), b"rfc.txt\x00Hi There",
                       _hashlib.sha256).hexdigest()
    check("hmac cross-checks against Python hmac", sig.get("hmac") == expect,
          str(sig.get("hmac")) + " vs " + expect)
    check("sig binds filename", sig.get("file") == "rfc.txt", str(sig))
    check("sig algorithm id", sig.get("algorithm") == "HMAC-SHA256", str(sig))
    p = run(tg, "sign", "--gen-key", "k.hex", cwd=sdir)
    check("gen-key exit 0", p.returncode == 0, p.stderr)
    keytext = open(os.path.join(sdir, "k.hex"), encoding="utf-8").read().strip()
    check("gen-key 32 bytes hex",
          len(keytext) == 64 and all(c in "0123456789abcdef" for c in keytext),
          keytext[:20])
    p = run(tg, "sign", "--in", "data.txt", "--sig", "data.sig",
            "--key-file", "k.hex", cwd=sdir)
    check("sign exit 0", p.returncode == 0, p.stderr)
    p = run(tg, "verify", "--in", "data.txt", "--sig", "data.sig",
            "--key-file", "k.hex", cwd=sdir)
    check("verify VALID exit 0", p.returncode == 0 and "VALID " in p.stdout, p.stdout)
    write(os.path.join(sdir, "data.txt"), "important bytes?\n")
    p = run(tg, "verify", "--in", "data.txt", "--sig", "data.sig",
            "--key-file", "k.hex", cwd=sdir)
    check("tampered exit 2", p.returncode == 2 and "INVALID" in p.stdout, p.stdout)
    write(os.path.join(sdir, "data.txt"), "important bytes\n")
    p = run(tg, "sign", "--gen-key", "k2.hex", cwd=sdir)
    check("gen-key2 exit 0", p.returncode == 0, p.stderr)
    p = run(tg, "verify", "--in", "data.txt", "--sig", "data.sig",
            "--key-file", "k2.hex", cwd=sdir)
    check("wrong key exit 2", p.returncode == 2, f"got {p.returncode}")
    _shutil.copy(os.path.join(sdir, "data.txt"), os.path.join(sdir, "other.txt"))
    _shutil.copy(os.path.join(sdir, "data.sig"), os.path.join(sdir, "other.sig"))
    patched = json.load(open(os.path.join(sdir, "other.sig"), encoding="utf-8"))
    patched["file"] = "other.txt"
    json.dump(patched, open(os.path.join(sdir, "other.sig"), "w"))
    p = run(tg, "verify", "--in", "other.txt", "--sig", "other.sig",
            "--key-file", "k.hex", cwd=sdir)
    check("patched transplant exit 2", p.returncode == 2 and "INVALID" in p.stdout,
          p.stdout)
    p = run(tg, "verify", "--in", "data.txt", "--sig", "data.sig", cwd=sdir)
    check("no key exit 1", p.returncode == 1, f"got {p.returncode}")
    write(os.path.join(sdir, "bad.sig"), "not json{{{")
    p = run(tg, "verify", "--in", "data.txt", "--sig", "bad.sig",
            "--key-file", "k.hex", cwd=sdir)
    check("garbage sig exit 1", p.returncode == 1, f"got {p.returncode}")

    # --- 14. wrap: capture + claims skeleton + exit passthrough ---
    wdir = os.path.join(tmp, "wrap")
    os.makedirs(wdir)
    p = run(tg, "wrap", "--out", "wclaims.json", "--log", "w.log", "--id", "W1",
            "--", tg, "--version", cwd=wdir)
    check("wrap exit 0", p.returncode == 0, p.stderr)
    wc = json.load(open(os.path.join(wdir, "wclaims.json"), encoding="utf-8"))
    check("wrap claim skeleton",
          wc["claims"][0]["id"] == "W1" and wc["claims"][0]["artifacts"] == ["w.log"],
          str(wc))
    check("wrap log captured",
          "tg " in open(os.path.join(wdir, "w.log"), encoding="utf-8").read())
    write(os.path.join(wdir, "wpolicy.json"), json.dumps({
        "require_file_citation": False, "require_test_citation": False,
        "require_artifact_citation": True, "quarantine_allow": True}))
    p = run(tg, "gate", "--claims", "wclaims.json", "--policy", "wpolicy.json",
            "--repo", ".", "--out", "wverdict.json", cwd=wdir)
    check("wrap->gate loop PASS", p.returncode == 0, f"got {p.returncode}: {p.stdout}")
    p = run(tg, "wrap", "--out", "q.json", "--log", "q.log",
            "--", "echo", "hello world", cwd=wdir)
    check("wrap spaced arg exit 0", p.returncode == 0, p.stderr)
    check("wrap quotes spaced args",
          "hello world" in open(os.path.join(wdir, "q.log"), encoding="utf-8").read())
    p = run(tg, "wrap", "--out", "f.json", "--log", "f.log", "--", tg, "nope", cwd=wdir)
    check("failing command exit passthrough",
          p.returncode == 1 and os.path.isfile(os.path.join(wdir, "f.json"))
          and os.path.isfile(os.path.join(wdir, "f.log")), f"got {p.returncode}")
    p = run(tg, "wrap", "--out", "x.json", cwd=wdir)
    check("missing -- exit 1", p.returncode == 1, f"got {p.returncode}")

    # --- 15. unicode filenames: hashed (not crashed/skipped), citable ---
    udir = os.path.join(tmp, "unicode")
    os.makedirs(udir)
    with open(os.path.join(udir, "snow-☃.txt"), "w", encoding="utf-8") as fh:
        fh.write("cold\n")
    p = run(tg, "fingerprint", "--path", udir, "--out", "u1.json", cwd=tmp)
    check("unicode fingerprint exit 0", p.returncode == 0, p.stderr)
    u1 = json.load(open(os.path.join(tmp, "u1.json"), encoding="utf-8"))
    check("unicode file hashed",
          any("snow-" in f.get("path", "") for f in u1.get("files", [])),
          str(u1.get("files")))
    p = run(tg, "fingerprint", "--path", udir, "--out", "u2.json", cwd=tmp)
    u2 = json.load(open(os.path.join(tmp, "u2.json"), encoding="utf-8"))
    check("unicode fingerprint stable", u1["id"] == u2["id"],
          f'{u1["id"]} vs {u2["id"]}')
    write(os.path.join(tmp, "uclaims.json"), json.dumps({
        "claims": [{"id": "U1", "text": "unicode",
                    "files": ["unicode/snow-☃.txt"],
                    "artifacts": ["unicode/snow-☃.txt"]}]}))
    write(os.path.join(tmp, "upolicy.json"), json.dumps({
        "require_file_citation": True, "require_test_citation": False,
        "require_artifact_citation": True, "quarantine_allow": True}))
    p = run(tg, "gate", "--claims", "uclaims.json", "--policy", "upolicy.json",
            "--repo", ".", "--out", "uverdict.json", cwd=tmp)
    check("unicode gate PASS", p.returncode == 0, f"got {p.returncode}: {p.stdout}")
    big_script = ("print('WRAP-BIG-START'); print('0123456789abcdef' * 4096); "
                  "print('WRAP-BIG-MID'); print('0123456789abcdef' * 4096); "
                  "print('WRAP-BIG-END')")
    p = run(tg, "wrap", "--out", "big.json", "--log", "big.log", "--",
            sys.executable, "-c", big_script, cwd=wdir)
    check("wrap big output exit 0", p.returncode == 0, p.stderr)
    biglog = open(os.path.join(wdir, "big.log"), encoding="utf-8").read()
    check("wrap big output complete",
          "WRAP-BIG-START" in biglog and "WRAP-BIG-MID" in biglog
          and "WRAP-BIG-END" in biglog and len(biglog) > 100000, str(len(biglog)))

    print(f"\n{len(FAILURES)} failures in {tmp}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
