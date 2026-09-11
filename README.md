# TrustGate (`tg`) — Local Trust Gate for AI-Written Code

[![CI](https://github.com/ZachDreamZ/trustgate/actions/workflows/ci.yml/badge.svg)](https://github.com/ZachDreamZ/trustgate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ZachDreamZ/trustgate)](https://github.com/ZachDreamZ/trustgate/releases)
[![License](https://img.shields.io/github/license/ZachDreamZ/trustgate)](LICENSE)

Single static binary. Local-first. Code never leaves your machine.

`tg gate` blocks AI-code merges unless every AI claim cites exact files, tests,
and runtime artifacts — with environment-reproducibility fingerprinting and
flake-aware quarantine built in.

```text
tg gate --claims claims.json --junit results.xml
# DENY: 2 uncited claims, 1 failed test  (exit 2)
# verdict.json + results.sarif written
```

## Why this exists (and what it is not)

Validated gap (web research, Sept 2026): teams moved from "can AI code?" to
"can I trust it in production?" Existing OSS covers adjacent niches only:

| Crowded niche | Examples | What TrustGate does instead |
|---|---|---|
| Agent observability / tracing | AgentOps, Langfuse, 5+ AgentTrace clones | Adversarial **verification** of claims, not trace logging |
| Flaky-test dashboards | rwx Captain, pytest-flakehunter | Systemic quarantine wired **into the merge gate** |
| Multiplayer agent workspaces | OpenAgents (3.7k stars) | Local policy enforcement, no collaboration server |
| API diff detectors | Azure oad, oasdiff, breakwatch | Semantic trust + repro parity, not syntactic diff |
| Auto-fix PR bots | mendapi (Dependabot-for-APIs) | Never auto-fixes. **Attests + blocks**, offline, auditable |

No OSS combines evidence-enforcement + repro fingerprint + flake quarantine in
one offline binary. That is the unoccupied niche (see also YC Fall 2026 RFS:
trust layer, self-maintaining APIs, compliance infra).

## Install

Download a prebuilt binary from
[GitHub Releases](https://github.com/ZachDreamZ/trustgate/releases)
(`tg-windows-x64.zip` / `tg-linux-x64.tar.gz`, each bundled with LICENSE
and README), or build from source below. Releases are cut from `v*` tags,
kept in sync with the project version.

## Quickstart

Prerequisites: CMake >= 3.20 and a C++17 compiler (MSVC 2022 BuildTools,
GCC >= 9, Clang >= 10). **Zero external dependencies** — STL only.

```bat
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
.\build\Release\tg.exe --version
ctest --test-dir build -C Release --output-on-failure
```

```sh
cmake -S . -B build -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/tg --version
ctest --test-dir build --output-on-failure
```

## Usage

```sh
tg init [--path DIR] [--lenient] [--force]
tg gate --claims claims.json [--policy .trustgate/policy.json] [--repo .]
        [--junit results.xml ...] [--quarantine quarantine.yml]
        [--lenient] [--out verdict.json] [--sarif results.sarif]
tg fingerprint [--path DIR] [--out repro.json] [--env NAME ...]
tg fingerprint --compare old.json new.json [--out diff.json]
tg flake --junit results.xml [...] [--history .trustgate/flake-history.jsonl]
         [--out quarantine.yml] [--min-runs 3] [--ttl-days 14]
         [--clusters-out clusters.json] [--min-sim 0.5]
tg eval [--dir evals] [--repo .] [--out eval-results.json] [--filter SUBSTR]
tg eval --trend [--last N]
tg sign --gen-key KEYFILE
tg sign --in FILE --sig SIGFILE [--key HEX | --key-file F | --key-env N]
tg verify --in FILE --sig SIGFILE [--key HEX | --key-file F | --key-env N]
```

Exit codes: `0` pass (or warn-only), `2` DENY / eval FAIL / INVALID signature,
`4` fingerprint drift, `1` usage/IO error, `3` not implemented (`wrap`).

### claims.json

```json
{
  "claims": [
    {
      "id": "C1",
      "text": "Fix NPE in auth refresh",
      "files": ["src/auth.cpp:10-25"],
      "tests": ["AuthTest.RefreshToken"],
      "artifacts": ["logs/test.log"]
    }
  ]
}
```

File refs: `path[:start[-end]]`. Test refs must exactly match a JUnit
`classname.name` (or bare `name`) **and** have passed. Failed-but-quarantined
tests degrade to warnings when the policy allows it.

## Layout

```text
src/main.cpp                 CLI dispatch
src/cli/commands.*           init|gate|fingerprint|flake|eval|sign|verify (+ wrap stub)
src/core/json.*              minimal JSON parser/serializer (sufficient subset)
src/core/fsutil.*            file IO, FNV-1a-64 hashing (BLAKE3 upgrade path)
src/core/mmap.*              memory-mapped file reads (Windows + POSIX)
src/core/proc.*              best-effort process capture for toolchain probes
src/attest/sha256.*          FIPS 180-4 SHA-256, stdlib-only
src/attest/sign.*            HMAC-SHA256 attestations, key loading
src/evidence/policy.*        JSON policy engine (Rego-lite equivalent)
src/evidence/claims.*        claims loader + file-ref grammar
src/evidence/verifier.*      citation checker -> findings + verdict
src/evidence/sarif.*         minimal SARIF 2.1.0 writer
src/eval/eval.*              deterministic eval scenarios + runner
src/repro/fingerprint.*      directory fingerprint + compare/diff + hash cache
src/flake/junit.*            tolerant JUnit XML scanner (captures failure text)
src/flake/quarantine.*       JSONL history, flake scoring, quarantine.yml
src/flake/category.*         heuristic root-cause classifier
src/flake/cluster.*          systemic co-occurrence clustering
tests/smoke.py               end-to-end CTest smoke (fixture repo in tmpdir)
schemas/policy.schema.json   policy JSON Schema (draft-07)
.github/workflows/ci.yml     windows-latest + ubuntu-latest
```

## Roadmap

Shipped: evidence gate, repro fingerprint (threads/mmap/cache), flake triage
with root-cause ranking and systemic co-occurrence clustering, EvalOps Lite
(`tg eval`), HMAC-SHA256 attestations (`tg sign` / `tg verify`), reusable
action, tagged releases with prebuilt binaries.

Next: `tg wrap` (agent output capture), SARIF rules metadata, timing-based
cause rules, VS Code extension.
- Hardening path (no behavior change): BLAKE3 file hashing, SQLite evidence
  store (replacing JSONL), libgit2 diff (replacing `git` shell-out),
  tree-sitter symbol refs, GoogleTest unit suite.

## Benchmarks

See [BENCHMARKS.md](BENCHMARKS.md) for methodology and latest numbers
(MSVC Release, Windows). Reproduce with
`python bench/bench.py --tg build/Release/tg.exe`.

## Use in CI

```yaml
- uses: ZachDreamZ/trustgate@main
  with:
    claims: claims.json
    junit: results.xml
    policy: .trustgate/policy.json
```

Inputs: `binary` (prebuilt `tg`, skips the source build), `source-dir`
(build an existing checkout, e.g. `'.'` for self-hosting), `tool-ref`,
`release-tag` (download a prebuilt `tg` from a published release instead
of building — fastest, e.g. `release-tag: v0.1.0`),
`working-directory`, `junit`, `policy`, `quarantine`, `lenient`,
`fail-on-deny`, `out`, `sarif`. Output: `verdict`
(`PASS` / `PASS_WITH_WARNINGS` / `DENY`). The exit code is 2 on DENY unless
`lenient` or `fail-on-deny: 'false'`. This repo dogfoods the action on every
push — see `dogfood/` and `.github/workflows/ci.yml`.

## Contributing

Keep it stdlib-only until v1.0. Every new check needs a `tests/smoke.py`
scenario. Run `ctest` before pushing.

## License

Apache-2.0. See [LICENSE](LICENSE).
