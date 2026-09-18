# AGENTS.md

## Project
TrustGate (`tg`) is a local-first C++17 trust gate for AI-written code. It verifies that agent claims are backed by exact file citations, passing tests, and runtime artifacts before code is accepted.

Core properties:
- single static binary
- zero external runtime dependencies
- local/offline verification
- fail-closed behavior for malformed or unverifiable evidence
- reproducibility fingerprints using SHA-256
- flaky-test quarantine and clustering
- eval, attestation, SARIF, and reusable GitHub Action support

## Start here
Read these files before making changes:
1. `README.md`
2. `SECURITY.md`
3. `CMakeLists.txt`
4. the focused test file for the subsystem you are changing

Primary subsystem map:
- `src/evidence/`: claims, policy, verification, SARIF
- `src/repro/`: reproducibility fingerprints
- `src/flake/`: JUnit history, quarantine, clustering
- `src/eval/`: deterministic eval runner
- `src/attest/`: SHA-256 and HMAC attestations
- `src/core/`: filesystem, JSON, mmap, process helpers
- `src/cli/`: command implementations
- `schemas/`: public JSON schemas
- `tests/`: integration and security regressions

## Build and test
Linux:
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Windows:
```bat
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Security/sanitizer coverage:
```sh
cmake -S . -B build-san -DCMAKE_BUILD_TYPE=Debug -DTG_ENABLE_SANITIZERS=ON
cmake --build build-san
ctest --test-dir build-san --output-on-failure
```

## Change rules
- Keep the project stdlib-only until the repository explicitly changes that policy.
- Prefer small, reviewable patches.
- Every new verification rule needs a focused regression test.
- Security-sensitive changes must fail closed.
- Never weaken path-containment, signature, checksum, or provenance checks to make tests pass.
- Preserve deterministic outputs where practical.
- Keep public schema changes backward-compatible or document the migration clearly.
- Do not put secrets, private vulnerability details, or exploit payloads in public issues or commits.

## Pull requests
Before opening or updating a PR:
- run the smallest relevant focused test
- run full CTest when behavior changes
- run sanitizer tests for parser, filesystem, crypto, or verifier changes
- explain behavior changes and compatibility impact
- link the issue being addressed

## Issue tags
Issue bodies use machine-readable `Tags:` lines so crawlers and agents can classify work even if GitHub labels are unavailable.

Common tags:
`agent-discovery`, `security`, `evidence`, `reproducibility`, `flake`, `evals`, `attestation`, `sarif`, `cli`, `ci`, `release`, `performance`, `windows`, `linux`, `docs`, `dx`, `testing`.

## Agent completion criteria
A task is complete only when:
- the requested behavior is implemented,
- relevant tests pass,
- no unrelated behavior is weakened,
- docs/schema examples are updated when user-facing behavior changes,
- the final response reports exactly what changed and what was verified.
