# Security Policy

TrustGate is a security-sensitive local verification tool. Please report suspected vulnerabilities privately so users have a chance to update before technical details are made public.

## Supported versions

| Version | Security support |
| --- | --- |
| `main` | Supported for development fixes |
| Latest tagged release | Supported |
| Older tagged releases | Upgrade to the latest release before requesting a backport |

Security fixes may land on `main` before a new tagged release is cut. Release notes will call out security-relevant changes when disclosure is appropriate.

## Reporting a vulnerability

**Do not include exploit details, secrets, proof-of-concept payloads, or affected-user data in a public issue, discussion, pull request, or commit.**

Use the repository's **Security** tab and choose **Report a vulnerability** when GitHub private vulnerability reporting is available. If that option is unavailable, open a public issue containing only a request for a private security-reporting channel; do not include vulnerability details. A maintainer can then move the discussion to a private channel.

A useful private report includes:

- the affected TrustGate version or commit;
- the operating system and invocation path involved;
- the security boundary you expected TrustGate to enforce;
- minimal reproduction steps and impact;
- whether the issue is already public or known to be exploited;
- any suggested mitigation, if you have one.

## What to expect

After a maintainer reviews the private report, the expected process is to confirm receipt, reproduce and scope the issue, coordinate a fix and regression test, and decide whether a release or advisory is needed. Timing depends on severity and maintainer availability; please keep technical details private until a fix or coordinated disclosure is ready.

If the report is not a security vulnerability, it may be redirected to the normal issue tracker after sensitive details have been removed.

## Security-sensitive areas

Changes to the following areas deserve heightened review:

- `.github/workflows/` and release configuration;
- `action.yml` and release-download verification;
- `src/attest/`, `src/evidence/`, and `src/repro/`;
- policy/eval schemas and trust-boundary parsing;
- cryptographic or hashing code;
- code that resolves repository-relative files or executes commands.
