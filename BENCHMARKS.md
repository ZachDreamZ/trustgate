# TrustGate benchmarks

Method: `python bench/bench.py --tg <tg-binary> [--work DIR]`
(`--work` defaults to a fresh tmpdir; reuse a dir only with a new path —
the script does not overwrite existing fixture trees.)

Machine (all numbers below): Windows 11, MSVC 19.44 Release build,
NVMe SSD, Windows Defender default settings.

## v0.2-dev: mmap reads + validated hash cache

| Benchmark | Result | Notes |
|---|---|---|
| `ctest` suite (35 checks) | 100% pass | incl. cache ID-stability + reuse assertions |
| Fingerprint, 50 files / 524 MB, uncached (mmap) | **1.28 s (~410 MB/s)** | zero-copy page-cache reads |
| Fingerprint, same tree, cached rerun | **0.11 s, 50/50 reused (11.7×)** | stable ID; single-change rerun rehashes 1 file, ID changes correctly |
| Fingerprint, 5,001 small files, cached rerun | 0.55 s | ≈ wash vs 0.51 s uncached warm — see honesty note |
| Fingerprint, 5,000 files, uncached warm | 0.51 s | mmap+threads (was 0.77 s) |

Honesty note: the cache stores size+mtime-ticks+hash per path and
skips I/O on exact hits. On warm small-file trees the cache's own JSON
round-trip costs about as much as re-hashing, so it breaks even there; it
wins big whenever hashing dominates (large files: 11.7×) or reads are cold
(skips AV-taxed first-touch reads). Corrupt/version-mismatched caches start
fresh and never fail a run. Fixed en route, twice: (1) a real int64-overflow
bug where Windows `file_clock` nanoseconds-since-1601 exceeded `LLONG_MAX`
and silently disabled the cache; (2) a wrong `mtime >= 0` assumption —
libstdc++ `file_clock` values are legitimately negative (epoch is
implementation-defined), so stat success is now tracked with an explicit
flag instead of a sentinel. Both were caught by the new smoke assertions,
and the second was root-caused by reproducing the exact CI failure in WSL
with a GCC build.

## v0.1.1-dev: portable thread-pool hashing (`std::thread`, no TBB)

| Benchmark | Result | Notes |
|---|---|---|
| `ctest` suite (29 checks) | 100% pass, ~1.9 s | |
| Binary size | 261 KB | stdlib-only, dynamic CRT |
| Fingerprint, 5,000 files / 10.5 MB, warm | **505 ms** | was 767 ms single-threaded (1.5×) |
| Fingerprint, 5,000 files, cold (freshly written) | **2.6 s** | was 20.1 s; first-touch AV/FS tax, overlapped by parallel reads |
| Fingerprint, 46 files | 216 ms cold / 82 ms warm | dominated by 2× `cmd.exe` probe spawns; `--no-probe` skips them (different ID — documented) |
| Fingerprint, 23 files (this repo's `src/`) | 94 ms | |
| Gate, 200 / 2,000 claims+tests | 116 ms / 916 ms (~0.5 ms/claim) | unchanged (gate is not hashed in parallel) |
| Process spawn (`tg --version`) | 23 ms | |
| Stability | same tree → same ID across runs, sessions **and** the single→multi-thread change (`01dc5295…`, `06d6a015…` reproduced exactly) | order-independent combine verified |

## v0.1.0 baseline (single-threaded hashing)

| Benchmark | Result |
|---|---|
| Fingerprint, 5,000 files / 10.5 MB, warm | 767 ms |
| Fingerprint, 5,000 files, cold | 20.1 s |
| Fingerprint, 46 files | 264 ms cold / 82 ms warm |
| Gate, 200 / 2,000 claims | 118 ms / 927 ms |

## Reading the cold numbers honestly

On the cold run `user+sys` CPU time was ~0.03 s while wall time was seconds:
the bottleneck is Windows Defender / filesystem first-touch scanning of new
files, not hashing. Warm runs measure TrustGate itself. The thread pool still
helps cold runs (7.7×) by overlapping scan latency across cores.

Threading kicks in at ≥64 files (below that, single-threaded to avoid
pool overhead), capped at 16 workers. Directory walk stays single-threaded;
only file reads+hashes parallelize, and results combine in sorted order so
IDs are deterministic.
