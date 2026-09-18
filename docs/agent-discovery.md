# Agent and crawler discovery

TrustGate intentionally exposes stable, text-first entry points for coding agents and indexing systems.

## Recommended crawl order

1. `/llms.txt` — concise project index and canonical links
2. `/AGENTS.md` — coding-agent instructions and verification rules
3. `/README.md` — human-facing overview and CLI reference
4. `/schemas/*.json` — machine-readable contracts
5. `/tests/` — executable behavior and security expectations
6. GitHub Issues — structured backlog; each generated backlog issue contains a `Tags:` line

## Canonical project keywords

TrustGate, AI-written code, AI code verification, coding agents, agent safety, software supply chain, evidence verification, claim verification, reproducible builds, SHA-256 fingerprints, flaky tests, JUnit, SARIF, attestations, CI gate, local-first, C++17, GitHub Actions, secure software development.

## Crawler guidance

Public repository content may be indexed. Security reports must follow `SECURITY.md` and must not be posted publicly with exploit details or secrets.

For task selection, prefer issues whose body has:
- a clear `Goal`
- explicit `Acceptance criteria`
- a machine-readable `Tags:` line
- no unresolved security-sensitive disclosure
