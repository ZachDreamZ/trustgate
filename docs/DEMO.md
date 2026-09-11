# TrustGate demo (transcript of real runs, v0.2.0)

A two-claim change where only one claim carries evidence.
`claims.json` cites `src/auth.cpp:1-3`, test `AuthTest.RefreshToken`, and
`logs/test.log` for C1; C2 says "also improved stuff" with no citations.

```console
$ tg gate --claims claims.json --junit results.xml --repo . --out verdict.json
TrustGate v0.2.0 gate: DENY (verdict.json)
  claims=2 errors=2 warnings=0 failed_tests=0
  warning: policy file not found: .trustgate/policy.json (using defaults)
  [error] uncited-files C2: claim 'C2' cites no files
  [error] uncited-tests C2: claim 'C2' cites no tests
$ echo $?
2
```

Drop the uncited claim and the gate passes:

```console
$ tg gate --claims claims.json --junit results.xml --repo . --out verdict.json
TrustGate v0.2.0 gate: PASS (verdict.json)
  claims=1 errors=0 warnings=0 failed_tests=0
  warning: policy file not found: .trustgate/policy.json (using defaults)
$ echo $?
0
```

Fingerprints are stable until a byte changes, and drift names the file:

```console
$ tg fingerprint --path src --out repro.json
fingerprint: da27f3c60c6ba3ca (1 files -> repro.json)
$ echo "// drift" >> src/auth.cpp
$ tg fingerprint --path src --out repro2.json
fingerprint: 2fe6a381db3a763c (1 files -> repro2.json)
$ tg fingerprint --compare repro.json repro2.json
DRIFT DETECTED da27f3c60c6ba3ca -> 2fe6a381db3a763c
  ~ auth.cpp
$ echo $?
4
```

A test failing 3 of 4 runs is quarantined with a suspected cause —
a test failing every run is reported as broken, not flaky, and left alone:

```console
$ tg flake --junit steady.xml --history hist.jsonl --out quarantine.yml
flake: 2 tests in run, 1 quarantined (-> quarantine.yml)
  ~ S.B rate=0.75 runs=4 cause=network (0.6)
clusters: 0 systemic groups
```

```yaml
# quarantine.yml
- id: S.B
  flake_rate: 0.75
  runs: 4
  ttl_days: 14
  reason: "flaky-network: 3 failures in last 4 runs"
  category: network
  confidence: 0.6
  signals: "connection refused"
```

Reproduce everything above with `tests/smoke.py` (`ctest` runs it), or point
`tg` at your own repo: `tg init && tg gate --claims claims.json`.
