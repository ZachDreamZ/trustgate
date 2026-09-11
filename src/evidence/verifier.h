#pragma once

// Citation checker: every AI claim must cite files/tests/artifacts that
// exist (and, for tests, have passed). Produces findings + verdict.

#include <map>
#include <string>
#include <vector>

#include "evidence/claims.h"
#include "evidence/policy.h"

namespace tg {

struct Finding {
    std::string rule;      // e.g. "uncited-tests", "missing-file"
    std::string claimId;   // claim id, or "" for file-level findings
    std::string message;
    std::string severity;  // "error" | "warning"
};

struct VerifyOptions {
    std::string repoRoot = ".";
    bool lenient = false;  // demote all errors to warnings
};

struct VerifyStats {
    int claims = 0;
    int errors = 0;
    int warnings = 0;
    int failedTests = 0;
    std::vector<std::string> quarantinedUsed;
};

struct VerifyReport {
    bool passed = false;
    std::vector<Finding> findings;
    VerifyStats stats;
};

// testStatus: JUnit test id -> 'P' | 'F' | 'S' (merged latest run).
// quarantinedIds: ids from quarantine.yml (honored only when policy allows).
VerifyReport verifyClaims(const std::vector<Claim>& claims, const Policy& policy,
                          const std::map<std::string, char>& testStatus,
                          const std::vector<std::string>& quarantinedIds,
                          const VerifyOptions& opts);

}  // namespace tg
