#include "cli/commands.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <sstream>

#include "core/fsutil.h"
#include "core/json.h"
#include "evidence/claims.h"
#include "evidence/policy.h"
#include "evidence/sarif.h"
#include "evidence/verifier.h"
#include "flake/junit.h"
#include "flake/quarantine.h"
#include "repro/fingerprint.h"

namespace tg {
namespace fs = std::filesystem;
namespace {

struct ParsedArgs {
    std::map<std::string, std::vector<std::string>> opts;
    std::vector<std::string> positionals;
};

bool isBoolFlag(const std::string& name, const std::vector<std::string>& boolFlags) {
    for (const std::string& b : boolFlags) {
        if (b == name) return true;
    }
    return false;
}

// Supports --key value, --key=value, and bare boolean --flag.
ParsedArgs parseFlags(const std::vector<std::string>& args,
                      const std::vector<std::string>& boolFlags) {
    ParsedArgs out;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a.rfind("--", 0) == 0 && a.size() > 2) {
            std::string key, value;
            std::string::size_type eq = a.find('=');
            if (eq != std::string::npos) {
                key = a.substr(2, eq - 2);
                value = a.substr(eq + 1);
            } else {
                key = a.substr(2);
                if (isBoolFlag(key, boolFlags)) {
                    value = "true";
                } else if (i + 1 < args.size() && args[i + 1].rfind("--", 0) != 0) {
                    value = args[++i];
                } else {
                    value = "";
                }
            }
            out.opts[key].push_back(value);
        } else {
            out.positionals.push_back(a);
        }
    }
    return out;
}

std::string optOnce(const ParsedArgs& p, const std::string& key, const std::string& dflt) {
    auto it = p.opts.find(key);
    if (it == p.opts.end() || it->second.empty()) return dflt;
    return it->second.back();
}

bool optBool(const ParsedArgs& p, const std::string& key) {
    return p.opts.find(key) != p.opts.end();
}

std::vector<std::string> optAll(const ParsedArgs& p, const std::string& key) {
    // Also comma-split so --junit a.xml,b.xml works.
    std::vector<std::string> out;
    auto it = p.opts.find(key);
    if (it == p.opts.end()) return out;
    for (const std::string& v : it->second) {
        std::istringstream in(v);
        std::string part;
        while (std::getline(in, part, ',')) {
            if (!part.empty()) out.push_back(part);
        }
    }
    return out;
}

int optInt(const ParsedArgs& p, const std::string& key, int dflt, std::string& error) {
    std::string s = optOnce(p, key, "");
    if (s.empty()) return dflt;
    try {
        return std::stoi(s);
    } catch (...) {
        error = "invalid integer for --" + key + ": " + s;
        return dflt;
    }
}

}  // namespace

void printTopHelp() {
    std::cout
        << "TrustGate v" << kTgVersion << " - local trust gate for AI-written code\n"
        << "Code never leaves your machine.\n"
        << "\n"
        << "Usage: tg <command> [options]\n"
        << "\n"
        << "  init          create .trustgate/policy.json starter policy\n"
        << "  gate          verify AI claims against files/tests/artifacts\n"
        << "  fingerprint   hash a directory tree into a stable repro ID\n"
        << "  flake         score JUnit history, emit quarantine.yml\n"
        << "  wrap|eval|sign  v1.0 roadmap (not implemented yet)\n"
        << "\n"
        << "Exit codes: 0 pass, 2 DENY/drift, 1 usage or IO error, 3 not implemented.\n"
        << "Run `tg <command> --help` for command options.\n";
}

int cmdStub(const std::string& name) {
    std::cout << "tg " << name << " is on the v1.0 roadmap (see README). Nothing to do.\n";
    return 3;
}

int cmdInit(const std::vector<std::string>& args) {
    ParsedArgs p = parseFlags(args, {"lenient", "force", "help"});
    if (optBool(p, "help")) {
        std::cout << "Usage: tg init [--path DIR] [--lenient] [--force]\n";
        return 0;
    }
    std::string dir = optOnce(p, "path", ".");
    bool lenient = optBool(p, "lenient");
    bool force = optBool(p, "force");
    std::string policyPath = dir + "/.trustgate/policy.json";
    if (fileExists(policyPath) && !force) {
        std::cerr << "policy already exists: " << policyPath << " (use --force to overwrite)\n";
        return 1;
    }
    if (!ensureParentDir(policyPath)) {
        std::cerr << "cannot create directory for: " << policyPath << "\n";
        return 1;
    }
    if (!writeFile(policyPath, defaultPolicyJson(lenient))) {
        std::cerr << "cannot write policy file: " << policyPath << "\n";
        return 1;
    }
    std::cout << "wrote " << policyPath << "\n"
              << "next: describe AI output in claims.json, then run\n"
              << "  tg gate --claims claims.json --junit results.xml --repo " << dir << "\n";
    return 0;
}

int cmdGate(const std::vector<std::string>& args) {
    ParsedArgs p = parseFlags(args, {"lenient", "help"});
    if (optBool(p, "help")) {
        std::cout << "Usage: tg gate --claims claims.json [--policy .trustgate/policy.json]\n"
                     "               [--repo .] [--junit results.xml ...]\n"
                     "               [--quarantine quarantine.yml] [--lenient]\n"
                     "               [--out verdict.json] [--sarif results.sarif]\n";
        return 0;
    }
    std::string claimsPath = optOnce(p, "claims", "");
    if (claimsPath.empty()) {
        std::cerr << "missing required --claims claims.json\n";
        return 1;
    }
    std::string policyPath = optOnce(p, "policy", ".trustgate/policy.json");
    std::string repo = optOnce(p, "repo", ".");
    std::string outPath = optOnce(p, "out", "verdict.json");
    std::string sarifPath = optOnce(p, "sarif", "");
    std::string quarantinePath = optOnce(p, "quarantine", "quarantine.yml");
    bool lenient = optBool(p, "lenient");
    std::vector<std::string> junitPaths = optAll(p, "junit");

    bool usedDefaults = false;
    std::string policyWarning;
    Policy policy = loadPolicy(policyPath, usedDefaults, policyWarning);

    std::vector<Claim> claims;
    try {
        claims = loadClaims(claimsPath);
    } catch (const std::exception& ex) {
        std::cerr << "cannot load claims: " << ex.what() << "\n";
        return 1;
    }

    std::map<std::string, char> testStatus;
    int junitTotal = 0;
    for (const std::string& jp : junitPaths) {
        JUnitReport rep;
        try {
            rep = parseJUnit(readFile(jp));
        } catch (const std::exception& ex) {
            std::cerr << "cannot read JUnit file '" << jp << "': " << ex.what() << "\n";
            return 1;
        }
        for (const TestCaseResult& tc : rep.cases) {
            // Worst status wins when shards overlap: F > S > P.
            auto it = testStatus.find(tc.id);
            if (it == testStatus.end()) {
                testStatus[tc.id] = tc.status;
            } else if (tc.status == 'F' || (tc.status == 'S' && it->second == 'P')) {
                it->second = tc.status;
            }
        }
        junitTotal += static_cast<int>(rep.cases.size());
    }

    std::vector<std::string> quarantinedIds;
    std::vector<QuarantineEntry> qlist = loadQuarantine(quarantinePath);
    for (const QuarantineEntry& e : qlist) quarantinedIds.push_back(e.id);

    VerifyOptions vopts;
    vopts.repoRoot = repo;
    vopts.lenient = lenient;
    VerifyReport report = verifyClaims(claims, policy, testStatus, quarantinedIds, vopts);

    std::string verdict =
        report.passed ? (report.stats.warnings > 0 ? "PASS_WITH_WARNINGS" : "PASS") : "DENY";
    JsonValue root = JsonValue::makeObject();
    root.object["tool"] = JsonValue::makeString("trustgate");
    root.object["version"] = JsonValue::makeString(kTgVersion);
    root.object["verdict"] = JsonValue::makeString(verdict);
    JsonValue stats = JsonValue::makeObject();
    stats.object["claims"] = JsonValue::makeNumber(report.stats.claims);
    stats.object["errors"] = JsonValue::makeNumber(report.stats.errors);
    stats.object["warnings"] = JsonValue::makeNumber(report.stats.warnings);
    stats.object["failed_tests"] = JsonValue::makeNumber(report.stats.failedTests);
    stats.object["junit_tests"] = JsonValue::makeNumber(junitTotal);
    JsonValue qused = JsonValue::makeArray();
    for (const std::string& q : report.stats.quarantinedUsed) {
        qused.array.push_back(JsonValue::makeString(q));
    }
    stats.object["quarantined_used"] = qused;
    root.object["stats"] = stats;
    JsonValue findings = JsonValue::makeArray();
    for (const Finding& f : report.findings) {
        JsonValue o = JsonValue::makeObject();
        o.object["rule"] = JsonValue::makeString(f.rule);
        o.object["claim"] = JsonValue::makeString(f.claimId);
        o.object["severity"] = JsonValue::makeString(f.severity);
        o.object["message"] = JsonValue::makeString(f.message);
        findings.array.push_back(o);
    }
    root.object["findings"] = findings;

    ensureParentDir(outPath);
    if (!writeFile(outPath, toJson(root, true) + "\n")) {
        std::cerr << "cannot write verdict file: " << outPath << "\n";
        return 1;
    }
    if (!sarifPath.empty()) {
        ensureParentDir(sarifPath);
        if (!writeFile(sarifPath, buildSarif(report, kTgVersion))) {
            std::cerr << "cannot write SARIF file: " << sarifPath << "\n";
            return 1;
        }
    }

    std::cout << "TrustGate v" << kTgVersion << " gate: " << verdict << " (" << outPath << ")\n"
              << "  claims=" << report.stats.claims << " errors=" << report.stats.errors
              << " warnings=" << report.stats.warnings
              << " failed_tests=" << report.stats.failedTests << "\n";
    if (usedDefaults) std::cout << "  warning: " << policyWarning << "\n";
    for (const Finding& f : report.findings) {
        std::cout << "  [" << f.severity << "] " << f.rule << " " << f.claimId << ": "
                  << f.message << "\n";
    }
    return report.passed ? 0 : 2;
}

int cmdFingerprint(const std::vector<std::string>& args) {
    ParsedArgs p = parseFlags(args, {"help", "no-probe"});
    if (optBool(p, "help")) {
        std::cout << "Usage:\n"
                     "  tg fingerprint [--path DIR] [--out repro.json] [--env NAME ...]\n"
                     "                   [--no-probe]\n"
                     "  tg fingerprint --compare old.json new.json [--out diff.json]\n"
                     "NOTE: --no-probe skips toolchain probes (faster) but changes the ID.\n";
        return 0;
    }
    std::string compareA = optOnce(p, "compare", "");
    if (!compareA.empty()) {
        // --compare takes two positionals in `tg fingerprint --compare a b` form;
        // also accept --compare=a --compare=b repetition.
        std::vector<std::string> files = optAll(p, "compare");
        for (const std::string& pos : p.positionals) files.push_back(pos);
        if (files.size() != 2) {
            std::cerr << "--compare needs exactly two fingerprint files\n";
            return 1;
        }
        Fingerprint a, b;
        try {
            a = fingerprintFromJson(parseJson(readFile(files[0])));
            b = fingerprintFromJson(parseJson(readFile(files[1])));
        } catch (const std::exception& ex) {
            std::cerr << "cannot load fingerprint: " << ex.what() << "\n";
            return 1;
        }
        FpDiff d = diffFingerprints(a, b);
        bool same = d.added.empty() && d.removed.empty() && d.changed.empty();
        std::string outPath = optOnce(p, "out", "");
        if (!outPath.empty()) {
            JsonValue root = JsonValue::makeObject();
            auto arr = [&](const std::vector<std::string>& v) {
                JsonValue ja = JsonValue::makeArray();
                for (const std::string& s : v) ja.array.push_back(JsonValue::makeString(s));
                return ja;
            };
            root.object["added"] = arr(d.added);
            root.object["removed"] = arr(d.removed);
            root.object["changed"] = arr(d.changed);
            root.object["identical"] = JsonValue::makeBool(same);
            ensureParentDir(outPath);
            if (!writeFile(outPath, toJson(root, true) + "\n")) {
                std::cerr << "cannot write diff file: " << outPath << "\n";
                return 1;
            }
        }
        if (same) {
            std::cout << "fingerprints identical (" << a.id << ")\n";
            return 0;
        }
        std::cout << "DRIFT DETECTED " << a.id << " -> " << b.id << "\n";
        for (const std::string& s : d.added) std::cout << "  + " << s << "\n";
        for (const std::string& s : d.removed) std::cout << "  - " << s << "\n";
        for (const std::string& s : d.changed) std::cout << "  ~ " << s << "\n";
        return 4;
    }

    FingerprintOptions fopts;
    fopts.root = optOnce(p, "path", ".");
    fopts.envNames = optAll(p, "env");
    fopts.probeToolchain = !optBool(p, "no-probe");
    std::string outPath = optOnce(p, "out", "repro.json");
    // TrustGate's own outputs must not perturb the fingerprint when --out
    // lands inside the scanned tree (keeps back-to-back runs stable).
    fopts.excludeFilenames.push_back("repro.json");
    fopts.excludeFilenames.push_back("verdict.json");
    fopts.excludeFilenames.push_back("quarantine.yml");
    fopts.excludeFilenames.push_back(fs::path(outPath).filename().generic_string());
    FingerprintResult res = computeFingerprint(fopts);
    ensureParentDir(outPath);
    if (!writeFile(outPath, toJson(fingerprintToJson(res.fp), true) + "\n")) {
        std::cerr << "cannot write fingerprint file: " << outPath << "\n";
        return 1;
    }
    std::cout << "fingerprint: " << res.fp.id << " (" << res.fp.files.size() << " files -> "
              << outPath << ")\n";
    for (const std::string& w : res.warnings) std::cout << "  warning: " << w << "\n";
    if (res.skipped > 0) std::cout << "  skipped entries: " << res.skipped << "\n";
    return 0;
}

int cmdFlake(const std::vector<std::string>& args) {
    ParsedArgs p = parseFlags(args, {"help"});
    if (optBool(p, "help")) {
        std::cout << "Usage: tg flake --junit results.xml [...] "
                     "[--history .trustgate/flake-history.jsonl]\n"
                     "               [--out quarantine.yml] [--min-runs 3] [--max-runs 500]\n"
                     "               [--ttl-days 14]\n";
        return 0;
    }
    std::vector<std::string> junitPaths = optAll(p, "junit");
    if (junitPaths.empty()) {
        std::cerr << "missing required --junit results.xml\n";
        return 1;
    }
    std::string error;
    FlakeOptions fopts;
    fopts.minRuns = optInt(p, "min-runs", 3, error);
    fopts.maxRuns = optInt(p, "max-runs", 500, error);
    fopts.ttlDays = optInt(p, "ttl-days", 14, error);
    if (!error.empty()) {
        std::cerr << error << "\n";
        return 1;
    }
    std::string historyPath = optOnce(p, "history", ".trustgate/flake-history.jsonl");
    std::string outPath = optOnce(p, "out", "quarantine.yml");

    // Merge shards of one run: worst status wins (F > S > P).
    std::map<std::string, char> merged;
    int total = 0;
    for (const std::string& jp : junitPaths) {
        JUnitReport rep;
        try {
            rep = parseJUnit(readFile(jp));
        } catch (const std::exception& ex) {
            std::cerr << "cannot read JUnit file '" << jp << "': " << ex.what() << "\n";
            return 1;
        }
        for (const TestCaseResult& tc : rep.cases) {
            auto it = merged.find(tc.id);
            if (it == merged.end()) {
                merged[tc.id] = tc.status;
            } else if (tc.status == 'F' || (tc.status == 'S' && it->second == 'P')) {
                it->second = tc.status;
            }
        }
        total += static_cast<int>(rep.cases.size());
    }
    std::vector<std::pair<std::string, char>> runResults(merged.begin(), merged.end());
    std::vector<QuarantineEntry> quarantined =
        updateFlakeHistory(historyPath, runResults, fopts, error);
    if (!error.empty()) {
        std::cerr << error << "\n";
        return 1;
    }
    ensureParentDir(outPath);
    writeQuarantineYaml(outPath, quarantined);
    std::cout << "flake: " << total << " tests in run, " << quarantined.size()
              << " quarantined (-> " << outPath << ")\n";
    for (const QuarantineEntry& e : quarantined) {
        std::cout << "  ~ " << e.id << " rate=" << e.flakeRate << " runs=" << e.runs << "\n";
    }
    return 0;
}

}  // namespace tg
