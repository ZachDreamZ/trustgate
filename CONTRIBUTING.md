# Contributing to TrustGate

## Ground rules

- **Stdlib-only C++17.** No new third-party dependencies without opening an
  issue first. Rationale: single static binary, zero supply-chain surface,
  builds everywhere with just CMake + a compiler.
- **Every new check needs a `tests/smoke.py` scenario.** If the smoke suite
  cannot demonstrate it end-to-end, the feature is not done.
- **Two compilers, zero warnings.** MSVC (`/W4`) and GCC/Clang
  (`-Wall -Wextra`) must both build warning-free.
- **Deterministic output.** Fingerprints, verdicts, quarantine files, and
  cluster reports must be byte-stable across runs on unchanged inputs.
  Sort everything; no timestamps in output files (history files excepted);
  no hash-map iteration in output paths.

## Workflow

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release  # or VS generator
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python bench/bench.py --tg build/Release/tg.exe  # for perf work
```

The repo dogfoods itself: `dogfood/claims.json` gates every CI run and
`evals/` scenarios must stay green. If your change breaks the dogfood gate,
either the change or the claims need updating — say which in the PR.

## Tests

`tests/smoke.py --tg <binary>` builds throwaway fixture repos and asserts
exit codes, verdict contents, fingerprint stability, quarantine scoring,
cluster grouping, and eval runs. Keep scenarios hermetic: pin fixture
mtimes with `pin_mtimes()` (see the hash-cache section) so assertions never
depend on wall-clock filesystem behavior.

## Commits

Short imperative summaries (`Add X`, `Fix Y`). One logical change per
commit. CI (windows + ubuntu, build + smoke + dogfood gate + action paths)
must be green before merge.
