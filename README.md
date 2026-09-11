# TrustGate (`tg`) — Local Trust Gate for AI-Written Code

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
```

Exit codes: `0` pass (or warn-only), `2` DENY / drift-detected,
`1` usage/IO error, `3` not implemented in this version (`wrap`, `eval`, `sign`).

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
src/cli/commands.*           init|gate|fingerprint|flake (+ wrap/eval/sign stubs)
src/core/json.*              minimal JSON parser/serializer (sufficient subset)
src/core/fsutil.*            file IO, FNV-1a-64 hashing (BLAKE3 upgrade path)
src/core/proc.*              best-effort process capture for toolchain probes
src/evidence/policy.*        JSON policy engine (Rego-lite equivalent)
src/evidence/claims.*        claims loader + file-ref grammar
src/evidence/verifier.*      citation checker -> findings + verdict
src/evidence/sarif.*         minimal SARIF 2.1.0 writer
src/repro/fingerprint.*      directory fingerprint + compare/diff
src/flake/junit.*            tolerant JUnit XML scanner
src/flake/quarantine.*       JSONL history, flake scoring, quarantine.yml
tests/smoke.py               end-to-end CTest smoke (fixture repo in tmpdir)
schemas/policy.schema.json   policy JSON Schema (draft-07)
.github/workflows/ci.yml     windows-latest + ubuntu-latest
```

## Roadmap

- **v0.2**: full SARIF rules metadata, GitHub Action (`trustgate-action`),
  heuristic root-cause ranking for quarantined tests.
- **v1.0**: systemic co-occurrence clustering, EvalOps Lite (`tg eval`),
  Ed25519 attestation (`tg sign`), agent wrapper (`tg wrap`).
- Hardening path (no behavior change): BLAKE3 file hashing, SQLite evidence
  store (replacing JSONL), libgit2 diff (replacing `git` shell-out),
  tree-sitter symbol refs, GoogleTest unit suite.

## Benchmarks

See [BENCHMARKS.md](BENCHMARKS.md) for methodology and latest numbers
(MSVC Release, Windows). Reproduce with
`python bench/bench.py --tg build/Release/tg.exe`.

## Contributing

Keep it stdlib-only until v1.0. Every new check needs a `tests/smoke.py`
scenario. Run `ctest` before pushing.

## License

Apache-2.0. See [LICENSE](LICENSE).
