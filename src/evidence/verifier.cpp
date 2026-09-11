#include "evidence/verifier.h"

#include "core/fsutil.h"

namespace tg {
namespace {

bool isAbsPath(const std::string& p) {
    if (p.empty()) return false;
    if (p[0] == '/' || p[0] == '\\') return true;
    return p.size() > 1 && p[1] == ':';  // Windows drive letter
}

std::string joinRepo(const std::string& root, const std::string& ref) {
    if (isAbsPath(ref)) return ref;
    std::string r = root;
    while (!r.empty() && (r.back() == '/' || r.back() == '\\')) r.pop_back();
    if (r.empty() || r == ".") return ref;
    return r + "/" + ref;
}

bool containsId(const std::vector<std::string>& list, const std::string& id) {
    for (const std::string& e : list) {
        if (e == id) return true;
    }
    return false;
}

}  // namespace

VerifyReport verifyClaims(const std::vector<Claim>& claims, const Policy& policy,
                          const std::map<std::string, char>& testStatus,
                          const std::vector<std::string>& quarantinedIds,
                          const VerifyOptions& opts) {
    VerifyReport report;
    report.stats.claims = static_cast<int>(claims.size());

    auto add = [&](const std::string& rule, const std::string& claimId,
                   const std::string& msg, bool isError) {
        Finding f;
        f.rule = rule;
        f.claimId = claimId;
        f.message = msg;
        f.severity = (isError && !opts.lenient) ? "error" : "warning";
        report.findings.push_back(f);
        if (f.severity == "error") {
            ++report.stats.errors;
        } else {
            ++report.stats.warnings;
        }
    };

    for (const Claim& c : claims) {
        // ---- files ----
        if (c.files.empty() && policy.requireFileCitation) {
            add("uncited-files", c.id, "claim '" + c.id + "' cites no files", true);
        }
        for (const std::string& ref : c.files) {
            FileRef fr;
            if (!parseFileRef(ref, fr)) {
                add("bad-file-ref", c.id, "claim '" + c.id + "': malformed file ref '" + ref + "'",
                    true);
                continue;
            }
            std::string full = joinRepo(opts.repoRoot, fr.path);
            if (!fileExists(full)) {
                add("missing-file", c.id,
                    "claim '" + c.id + "': cited file not found '" + fr.path + "'", true);
                continue;
            }
            if (fr.hasRange) {
                long lines = countFileLines(full);
                if (lines < 0) {
                    add("missing-file", c.id,
                        "claim '" + c.id + "': cannot read cited file '" + fr.path + "'", true);
                } else if (fr.end > lines) {
                    add("bad-line-range", c.id,
                        "claim '" + c.id + "': range " + std::to_string(fr.start) + "-" +
                            std::to_string(fr.end) + " exceeds " + std::to_string(lines) +
                            " lines in '" + fr.path + "'",
                        true);
                }
            }
        }
        // ---- tests ----
        if (c.tests.empty() && policy.requireTestCitation) {
            add("uncited-tests", c.id, "claim '" + c.id + "' cites no tests", true);
        }
        for (const std::string& t : c.tests) {
            auto it = testStatus.find(t);
            if (it == testStatus.end()) {
                add("unknown-test", c.id,
                    "claim '" + c.id + "': no evidence for test '" + t +
                        "' (absent from JUnit results)",
                    true);
                continue;
            }
            if (it->second == 'F') {
                ++report.stats.failedTests;
                if (policy.quarantineAllow && containsId(quarantinedIds, t)) {
                    add("quarantined-failure", c.id,
                        "claim '" + c.id + "': test '" + t +
                            "' failed but is quarantined (allowed)",
                        false);
                    if (!containsId(report.stats.quarantinedUsed, t)) {
                        report.stats.quarantinedUsed.push_back(t);
                    }
                } else {
                    add("failed-test", c.id,
                        "claim '" + c.id + "': cited test '" + t + "' failed", true);
                }
            } else if (it->second == 'S') {
                add("skipped-test", c.id,
                    "claim '" + c.id + "': cited test '" + t +
                        "' was skipped (not evidence)",
                    true);
            }
        }
        // ---- artifacts ----
        if (c.artifacts.empty() && policy.requireArtifactCitation) {
            add("uncited-artifacts", c.id, "claim '" + c.id + "' cites no artifacts", true);
        }
        for (const std::string& a : c.artifacts) {
            std::string full = joinRepo(opts.repoRoot, a);
            if (!fileExists(full)) {
                add("missing-artifact", c.id,
                    "claim '" + c.id + "': cited artifact not found '" + a + "'", true);
            }
        }
    }

    report.passed = (report.stats.errors == 0);
    return report;
}

}  // namespace tg
