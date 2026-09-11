# Changelog

All notable changes to TrustGate. Format follows Keep a Changelog;
versions follow Semantic Versioning (`tg --version`).

## [Unreleased]

## [0.3.0] — 2026-09-11

### Added
- `tg sign` / `tg verify` / `--gen-key`: HMAC-SHA256 file attestations with
  key loading (`--key` / `--key-file` / `--key-env`), filename
  cryptographically bound into the MAC, constant-time comparison.
- `tg wrap`: run a command, stream output to a log, emit a claims skeleton
  citing the log, and pass the wrapped exit code through. Documented shell
  execution, no timeout enforcement, 64MB disclosed log cap.
- CI dogfoods sign round-trips on the verdict every push.

### Fixed
- POSIX exit codes: `pclose` wait-status is now decoded (`WEXITSTATUS`,
  `128+signal`), so eval asserts and wrap passthrough see process truth.
- Streaming log capture: large outputs no longer truncate at 64KB and the
  child always drains, keeping exit codes truthful.
- Windows pipes read in binary mode (no CRLF translation, no Ctrl+Z EOF).

## [0.2.0] — 2026-09-11

### Added
- Parallel fingerprint hashing (`std::thread` pool, no TBB).
- Memory-mapped file reads and validated size+mtime hash cache.
- Flake root-cause ranking (timeout/race/network/resource/ordering/
  assertion/unknown) with confidence and signals in `quarantine.yml`.
- Systemic co-occurrence clustering (Jaccard + union-find + majority cause).
- EvalOps Lite (`tg eval`): typed asserts, trend history, dogfood evals.
- Action `release-tag` fast path (prebuilt download, no build).
- Badges, CONTRIBUTING, real-output demo (`docs/DEMO.md`), benchmarks.

### Fixed
- CI drives MSVC via Ninja (`windows-latest` has no VS instance for CMake).
- Hermetic smoke mtimes; `file_clock` treated as opaque (negative values
  are valid on libstdc++).

## [0.1.0] — 2026-09-11

Initial release: evidence gate (`tg gate` with JUnit/file/artifact
citations), reproducibility fingerprints, flake triage with quarantine,
stdlib-only C++17, CTest smoke suite, Windows+Linux CI, reusable GitHub
Action (source build), and tagged releases with prebuilt binaries.
