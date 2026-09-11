# TrustGate real-world validation

19 parallel field agents ran the current binary against real open-source
repos (shallow clones) plus synthetic torture trees, one shared protocol:
fingerprint twice (stability + timing), drift-and-restore (exit 4 + restore
equality), gate PASS (valid citations, exit 0) and DENY (bad citation,
exit 2 + rule), two repo-adapted evals, sign/verify round-trip. Full matrix
below; agents reported compact verdicts, two FAILs became fixes in this repo.

## Project matrix

| # | Project | Lang | Files | Size | FP warm | Gate | Eval | Sign | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| 1 | fmtlib/fmt | C++ | 145 | 4.3 MB | 108 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 2 | nlohmann/json | C++ | 1,235 | 25.9 MB | 227 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 3 | catchorg/Catch2 | C++ | 587 | 12 MB | 169 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 4 | psf/requests | Python | 128 | 7.3 MB | 106 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 5 | pallets/flask | Python | 236 | 4.8 MB | 115 ms | file gates + **real pytest gates** ✓ | PASS | VALID | PASS |
| 6 | axios/axios | JS | 467 | 4.6 MB | 112 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 7 | expressjs/express | JS | 213 | 1.4 MB | **crash → fixed** | PASS/DENY ✓ | PASS | VALID | PASS* |
| 8 | sharkdp/bat | Rust | 902 | 12 MB | **crash → fixed** | PASS/DENY ✓ | PASS | VALID | PASS* |
| 9 | BurntSushi/ripgrep | Rust | 236 | 3.9 MB | 105 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 10 | curl/curl | C | 4,503 | 34 MB | 546 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 11 | redis/redis | C | 1,855 | 31 MB | 724 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 12 | git/git | C | 4,847 | 70 MB | 558 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 13 | facebook/zstd | C | 568 | 10.7 MB | 132 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 14 | stedolan/jq | C | 427 | 6.0 MB | 355 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 15 | mochajs/mocha | JS | 675 | 4.5 MB | 145 ms | PASS/DENY ✓ | PASS | VALID | PASS |
| 16 | torvalds/linux | C | 95,705 | 1,604 MB | cold 76 s / warm 9.7 s | PASS/DENY ✓ | — | — | PASS |

PASS* = initial FAIL converted by a fix, re-verified on the same trees
(express stable `a0dfc517`, bat stable `76a37800` across 3 runs each).

Flask depth: the agent installed the package and ran the real suite
(487 ran, 485 passed, 1 failed), then gated one real passing test id
(`require_test_citation`, exit 0) and one nonexistent id (exit 2,
`unknown-test`). Only real-test-evidence run in the panel.

Linux stress: 9,848 files/s, 165 MB/s warm; cold run dominated by first-touch
I/O. Stable IDs, drift + restore exact, no crash at 95k files / 1.6 GB.

## Specialist results

**Edge filenames** (synthetic torture tree): unicode (CJK/emoji) dirs and
files, spaces, empty files, 5 MB file, 30-deep nesting, brackets, quotes,
trailing dot — all hashed, cited, drift-detected, JSON-valid. Two
platform notes: a 200-char filename (260-char full path) hits the Windows
`MAX_PATH` limit — now reported as a listed skip instead of a silent one
(see fix below); `dot.` normalizes to `dot` (OS behavior, handled
consistently); `Case.txt`/`case.txt` collide on case-insensitive Windows
(OS refusal, not a tool verdict).

**Negatives matrix** (10/10): `bad-file-ref`, `bad-line-range`,
`missing-file` (incl. directory-as-file), `unknown-test`, `skipped-test`,
`quarantined-failure` (warn, exit 0), `failed-test` without quarantine
(exit 2), malformed/missing claims (exit 1), invalid policy (warn +
defaults). Every exit code and rule id as specified.

**Release install** (new-user simulation from the v0.3.0 zip): binary solid
(download/extract/version/gate/fingerprint/eval/sign all work from docs +
`--help`), verdict PARTIAL on documentation. All five frictions fixed:
eval schema was undocumented → `schemas/eval.schema.json` + walkthrough;
no binary quickstart → 5-minute walkthrough in README; header comment
implied SARIF by default → corrected; `--policy` default confused with
`--repo` → default policy now travels with the scanned repo; `.trustgate/`
exclusion undisclosed → documented.

## Bugs the panel found (both fixed)

1. **Unicode fast-fail (express, bat).** Non-ASCII filenames
(`snow ☃`, `test.A—B가`) crashed the process (`0xC0000409`) in MSVC's
narrow path conversion. Fix: explicit UTF-8 handling end to end —
native walk, `WideCharToMultiByte(CP_UTF8)` for identity strings,
wide opens for reads (files now hash instead of being skipped),
`MultiByteToWideChar(CP_UTF8)` at every open/create/rename boundary.
Locked by new smoke coverage (hash + stability + gate citation of a
`snow-☃.txt` fixture).
2. **Silent skips (edge).** Over-long paths were counted but unnamed. Fix:
up to 50 skip paths are now printed with the count, so coverage gaps
cannot hide.

## Method notes

- Depth-1 clones, September 2026 upstreams. "Files" is tg-scanned files
  (`.git`/build outputs excluded). Two agents counted differently and an
  independent auditor reconciled both exactly: express 242 included 29
  `.git` files (213 scanned), bat 1007 was `git ls-files` including 93
  uninitialized submodule gitlinks (902 on disk after skips).
- Agents adapted README/LICENSE names per repo (`COPYING`, `LICENSE.txt`,
  `Readme.md` casing); adaptations are noted per row, not failures.
- Threat model honesty: agents verified behavior, not absence of all bugs;
  the 80-check smoke suite plus CI (Windows + Linux, GCC + MSVC) is the
  standing regression net.
