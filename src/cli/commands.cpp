#include "cli/commands.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <tuple>

#include "attest/sign.h"
#include "core/fsutil.h"
#include "core/json.h"
#include "core/proc.h"
#include "eval/eval.h"
#include "evidence/claims.h"
#include "evidence/policy.h"
#include "flake/cluster.h"
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
        << "  eval          run deterministic eval scenarios (evals/*.json)\n"
        << "  sign          HMAC-SHA256 sign a file (attestation)\n"
        << "  verify        verify a file signature (exit 2 when INVALID)\n"
        << "  wrap          run a command, capture output+exit as claim evidence\n"
        << "\n"
        << "Exit codes: 0 pass, 2 DENY / eval FAIL / INVALID signature,\n"
        << "  4 fingerprint drift, 1 usage or IO error, 3 not implemented.\n"
        << "Run `tg <command> --help` for command options.\n";
}

int cmdSign(const std::vector<std::string>& args) {
    ParsedArgs p = parseFlags(args, {"help"});
    if (optBool(p, "help")) {
        std::cout << "Usage:\n"
                     "  tg sign --gen-key KEYFILE\n"
                     "  tg sign --in FILE --sig SIGFILE [--key HEX | --key-file F | --key-env N]\n"
                     "Keys are hex (16..128 bytes); exactly one source. Exit 1 on usage/IO error.\n";
        return 0;
    }
    std::string genKey = optOnce(p, "gen-key", "");
    if (!genKey.empty()) {
        ensureParentDir(genKey);
        if (!writeFile(genKey, randomKeyHex() + "\n")) {
            std::cerr << "cannot write key file: " + genKey + "\n";
            return 1;
        }
        std::cout << "wrote 32-byte key: " + genKey + " (keep secret)\n";
        return 0;
    }
    std::string inPath = optOnce(p, "in", "");
    std::string sigPath = optOnce(p, "sig", "");
    if (inPath.empty() || sigPath.empty()) {
        std::cerr << "need --in FILE and --sig SIGFILE (or --gen-key KEYFILE)\n";
        return 1;
    }
    KeyLoad key = loadKey(optOnce(p, "key", ""), optOnce(p, "key-file", ""),
                          optOnce(p, "key-env", ""));
    if (!key.error.empty()) {
        std::cerr << key.error + "\n";
        return 1;
    }
    std::string data;
    try {
        data = readFile(inPath);
    } catch (const std::exception& ex) {
        std::cerr << std::string("cannot read input: ") + ex.what() + "\n";
        return 1;
    }
    std::string mac = attestationMac(key.bytes, inPath, data);
    JsonValue sig = JsonValue::makeObject();
    sig.object["file"] = JsonValue::makeString(inPath);
    sig.object["algorithm"] = JsonValue::makeString("HMAC-SHA256");
    sig.object["hmac"] = JsonValue::makeString(mac);
    ensureParentDir(sigPath);
    if (!writeFile(sigPath, toJson(sig, true) + "\n")) {
        std::cerr << "cannot write signature file: " + sigPath + "\n";
        return 1;
    }
    std::cout << "signed " + inPath + " -> " + sigPath + "\n";
    return 0;
}

int cmdVerify(const std::vector<std::string>& args) {
    ParsedArgs p = parseFlags(args, {"help"});
    if (optBool(p, "help")) {
        std::cout << "Usage: tg verify --in FILE --sig SIGFILE "
                     "[--key HEX | --key-file F | --key-env N]\n"
                     "Exit 0 VALID, 2 INVALID, 1 usage or IO error. The filename is\n"
                     "cryptographically bound into the MAC: transplanted or renamed\n"
                     "files verify INVALID even with identical bytes.\n";
        return 0;
    }
    std::string inPath = optOnce(p, "in", "");
    std::string sigPath = optOnce(p, "sig", "");
    if (inPath.empty() || sigPath.empty()) {
        std::cerr << "need --in FILE and --sig SIGFILE\n";
        return 1;
    }
    KeyLoad key = loadKey(optOnce(p, "key", ""), optOnce(p, "key-file", ""),
                          optOnce(p, "key-env", ""));
    if (!key.error.empty()) {
        std::cerr << key.error + "\n";
        return 1;
    }
    JsonValue sig;
    try {
        sig = parseJson(readFile(sigPath));
    } catch (const std::exception& ex) {
        std::cerr << std::string("cannot load signature: ") + ex.what() + "\n";
        return 1;
    }
    auto invalid = [&](const std::string& why) {
        std::cout << "INVALID (" + why + ")\n";
        return 2;
    };
    if (!sig.isObject() || sig.getString("algorithm", "") != "HMAC-SHA256") {
        return invalid("unsupported algorithm");
    }
    if (sig.getString("file", "") != inPath) {
        return invalid("filename mismatch (signature bound to '" + sig.getString("file", "") + "')");
    }
    std::vector<uint8_t> expected;
    if (!fromHex(sig.getString("hmac", ""), expected) || expected.size() != 32) {
        return invalid("malformed hmac");
    }
    std::string data;
    try {
        data = readFile(inPath);
    } catch (const std::exception& ex) {
        std::cerr << std::string("cannot read input: ") + ex.what() + "\n";
        return 1;
    }
    std::vector<uint8_t> actualBytes;
    // inPath == recorded path here (checked above); the MAC covers both.
    fromHex(attestationMac(key.bytes, inPath, data), actualBytes);
    if (actualBytes.size() != 32 || !constantTimeEqual(actualBytes.data(), expected.data(), 32)) {
        return invalid("hmac mismatch");
    }
    std::cout << "VALID " + inPath + "\n";
    return 0;
}

int cmdWrap(const std::vector<std::string>& args) {
    // Split raw args at the first "--": everything before is tg flags,
    // everything after is the wrapped command (argv items rejoined for sh).
    std::size_t sep = args.size();
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--") {
            sep = i;
            break;
        }
    }
    std::vector<std::string> flags(args.begin(), args.begin() + sep);
    std::vector<std::string> cmdTokens;
    if (sep + 1 < args.size()) cmdTokens.assign(args.begin() + sep + 1, args.end());

    ParsedArgs p = parseFlags(flags, {"help"});
    if (optBool(p, "help")) {
        std::cout << "Usage: tg wrap --out claims.json --log run.log [--id ID]\n"
                     "               [--text TEXT] -- <command> [args ...]\n"
                     "Runs the command, captures output+exit code, and writes a claims\n"
                     "skeleton citing the log as a runtime artifact. Files/tests stay\n"
                     "empty for the author to fill. Exit code is the wrapped\n"
                     "command's (outputs are always written first). The command runs\n"
                     "in a shell with user privileges and no timeout enforcement.\n"
                     "Logs stream to disk (64MB cap, disclosed in output when hit).\n";
        return 0;
    }
    if (cmdTokens.empty()) {
        std::cerr << "need a command after -- (e.g. tg wrap --out c.json --log r.log -- make test)\n";
        return 1;
    }
    std::string outPath = optOnce(p, "out", "claims.json");
    std::string logPath = optOnce(p, "log", "tg-wrap.log");
    std::string id = optOnce(p, "id", "run");
    if (id.empty()) {
        std::cerr << "--id must not be empty\n";
        return 1;
    }
    std::string cmdline;
    for (const std::string& tok : cmdTokens) {
        if (!cmdline.empty()) cmdline.push_back(' ');
        bool quote = tok.empty() || tok.find_first_of(" \t\"") != std::string::npos;
        if (quote) cmdline.push_back('"');
        cmdline += tok;
        if (quote) cmdline.push_back('"');
    }
    // NOTE: shell execution is by design (pipelines welcome); see help.
    // Output streams straight to the log file so large outputs stay
    // faithful (64MB cap, disclosed in output when hit).
    ensureParentDir(logPath);
    ProcResult r = runCaptureToFile(cmdline, logPath);
    if (r.exitCode == -1) {
        std::cerr << "cannot capture output (unwritable log or failed spawn): " + logPath + "\n";
        return 1;
    }
    std::string text = optOnce(p, "text", "");
    if (text.empty()) {
        text = cmdline + " (exit " + std::to_string(r.exitCode) + ")";
    }
    JsonValue claim = JsonValue::makeObject();
    claim.object["id"] = JsonValue::makeString(id);
    claim.object["text"] = JsonValue::makeString(text);
    claim.object["files"] = JsonValue::makeArray();
    claim.object["tests"] = JsonValue::makeArray();
    JsonValue arts = JsonValue::makeArray();
    arts.array.push_back(JsonValue::makeString(logPath));
    claim.object["artifacts"] = arts;
    JsonValue root = JsonValue::makeObject();
    JsonValue claims = JsonValue::makeArray();
    claims.array.push_back(claim);
    root.object["claims"] = claims;
    ensureParentDir(outPath);
    if (!writeFile(outPath, toJson(root, true) + "\n")) {
        std::cerr << "cannot write claims file: " + outPath + "\n";
        return 1;
    }
    std::cout << "wrap: exit " + std::to_string(r.exitCode) + " (" +
                     std::to_string(r.bytesWritten) + " bytes -> " + logPath + ", claims -> " +
                     outPath + ")" + (r.truncated ? " [log truncated at 64MB]" : "") + "\n";
    return r.exitCode;
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
    fopts.useCache = !optBool(p, "no-cache");
    fopts.cachePath = optOnce(p, "cache", "");
    if (fopts.cachePath.empty()) {
        std::string r = fopts.root;
        while (!r.empty() && (r.back() == '/' || r.back() == '\\')) r.pop_back();
        fopts.cachePath = (r.empty() ? std::string(".") : r) + "/.trustgate/fp-cache.json";
    }
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
                     "               [--ttl-days 14] [--clusters-out clusters.json]\n"
                     "               [--min-sim 0.5]\n";
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

    // Merge shards of one run: worst status wins (F > S > P), carrying the
    // winning outcome's failure evidence.
    std::map<std::string, FlakeSample> merged;
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
                FlakeSample s;
                s.id = tc.id;
                s.status = tc.status;
                s.message = tc.failureText;
                s.timeMs = tc.timeMs;
                merged[tc.id] = s;
            } else if (tc.status == 'F' || (tc.status == 'S' && it->second.status == 'P')) {
                it->second.status = tc.status;
                it->second.message = tc.failureText;
                it->second.timeMs = tc.timeMs;
            }
        }
        total += static_cast<int>(rep.cases.size());
    }
    std::vector<FlakeSample> runResults;
    for (const auto& kv : merged) runResults.push_back(kv.second);
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
        std::cout << "  ~ " << e.id << " rate=" << e.flakeRate << " runs=" << e.runs
                  << " cause=" << e.category << " (" << e.confidence << ")\n";
    }

    // Systemic clustering over the retained history (same file just updated).
    double minSim = 0.5;
    {
        std::string ms = optOnce(p, "min-sim", "");
        if (!ms.empty()) {
            try {
                minSim = std::stod(ms);
            } catch (...) {
                std::cerr << "invalid --min-sim (need 0 < sim <= 1)\n";
                return 1;
            }
            if (minSim <= 0.0 || minSim > 1.0) {
                std::cerr << "invalid --min-sim (need 0 < sim <= 1)\n";
                return 1;
            }
        }
    }
    std::vector<std::string> histLines;
    if (fileExists(historyPath)) {
        try {
            std::string ht = readFile(historyPath);
            std::istringstream hin(ht);
            std::string hl;
            while (std::getline(hin, hl)) {
                if (!hl.empty() && hl.back() == '\r') hl.pop_back();
                if (hl.find_first_not_of(" \t") == std::string::npos) continue;
                histLines.push_back(hl);
            }
        } catch (...) {
            // History already validated on write; a torn read just skips clustering.
        }
    }
    std::vector<Cluster> clusters = computeClusters(histLines, minSim);
    std::cout << "clusters: " << clusters.size() << " systemic group"
              << (clusters.size() == 1 ? "" : "s") << "\n";
    for (const Cluster& c : clusters) {
        std::cout << "  # [";
        for (std::size_t i = 0; i < c.members.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << c.members[i];
        }
        std::cout << "] together " << c.runsTogether << "/" << c.runsTotal
                  << " runs, suspected " << c.cause << " (" << c.confidence << ")\n";
    }
    std::string clustersOut = optOnce(p, "clusters-out", "");
    if (!clustersOut.empty()) {
        JsonValue croot = JsonValue::makeObject();
        JsonValue carr = JsonValue::makeArray();
        for (const Cluster& c : clusters) {
            JsonValue o = JsonValue::makeObject();
            JsonValue m = JsonValue::makeArray();
            for (const std::string& id : c.members) m.array.push_back(JsonValue::makeString(id));
            o.object["tests"] = m;
            o.object["runs_together"] = JsonValue::makeNumber(c.runsTogether);
            o.object["runs_total"] = JsonValue::makeNumber(c.runsTotal);
            o.object["cause"] = JsonValue::makeString(c.cause);
            o.object["confidence"] = JsonValue::makeNumber(c.confidence);
            carr.array.push_back(o);
        }
        croot.object["clusters"] = carr;
        ensureParentDir(clustersOut);
        if (!writeFile(clustersOut, toJson(croot, true) + "\n")) {
            std::cerr << "cannot write clusters file: " + clustersOut + "\n";
            return 1;
        }
    }
    return 0;
}

namespace {

void appendEvalHistory(const std::string& path, const std::string& name, bool pass,
                       long long ms) {
    ensureParentDir(path);
    std::ofstream out(path, std::ios::app);
    if (!out) return;  // history is best effort; results file is authoritative
    JsonValue line = JsonValue::makeObject();
    line.object["ts"] = JsonValue::makeString(utcNowIso());
    line.object["name"] = JsonValue::makeString(name);
    line.object["pass"] = JsonValue::makeBool(pass);
    line.object["ms"] = JsonValue::makeNumber(static_cast<double>(ms));
    out << toJson(line) << "\n";
}

int cmdEvalTrend(const std::string& historyPath, int lastN) {
    std::string text;
    try {
        text = readFile(historyPath);
    } catch (const std::exception&) {
        std::cerr << "no history yet: " << historyPath << " (run `tg eval` first)\n";
        return 1;
    }
    std::map<std::string, std::vector<std::tuple<std::string, bool, long long>>> runs;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;
        try {
            JsonValue r = parseJson(line);
            if (!r.isObject()) continue;
            std::string name = r.getString("name", "");
            if (name.empty()) continue;
            runs[name].push_back(std::make_tuple(r.getString("ts", ""),
                                                 r.getBool("pass", false),
                                                 static_cast<long long>(r.getNumber("ms", 0.0))));
        } catch (...) {
            continue;  // skip corrupt lines
        }
    }
    if (runs.empty()) {
        std::cerr << "no eval history in " << historyPath << "\n";
        return 1;
    }
    for (const auto& kv : runs) {
        const auto& v = kv.second;
        std::size_t from = v.size() > static_cast<std::size_t>(lastN) ? v.size() - lastN : 0;
        int ok = 0;
        long long tot = 0;
        for (std::size_t i = from; i < v.size(); ++i) {
            if (std::get<1>(v[i])) ++ok;
            tot += std::get<2>(v[i]);
        }
        long long n = static_cast<long long>(v.size() - from);
        std::cout << kv.first << ": " << ok << "/" << n << " passed, last "
                  << (std::get<1>(v.back()) ? "PASS" : "FAIL") << " " << std::get<0>(v.back())
                  << ", avg " << (n > 0 ? tot / n : 0) << "ms\n";
    }
    return 0;
}

}  // namespace

int cmdEval(const std::vector<std::string>& args) {
    ParsedArgs p = parseFlags(args, {"help"});
    if (optBool(p, "help")) {
        std::cout << "Usage:\n"
                     "  tg eval [--dir evals] [--repo .] [--out eval-results.json]\n"
                     "          [--history .trustgate/eval-history.jsonl] [--filter SUBSTR]\n"
                     "  tg eval --trend [--history ...] [--last N]\n"
                     "Exit codes: 0 all pass, 2 any failure, 1 usage or IO error.\n";
        return 0;
    }
    std::string historyPath = optOnce(p, "history", ".trustgate/eval-history.jsonl");
    if (p.opts.find("trend") != p.opts.end()) {
        int lastN = 10;
        std::string nstr = optOnce(p, "trend", "");
        if (nstr.empty()) nstr = optOnce(p, "last", "");
        if (!nstr.empty()) {
            try {
                lastN = std::stoi(nstr);
            } catch (...) {
                std::cerr << "invalid trend window: " + nstr + "\n";
                return 1;
            }
            if (lastN <= 0) lastN = 10;
        }
        return cmdEvalTrend(historyPath, lastN);
    }
    std::string dir = optOnce(p, "dir", "evals");
    std::string repo = optOnce(p, "repo", ".");
    std::string outPath = optOnce(p, "out", "eval-results.json");
    std::string filter = optOnce(p, "filter", "");

    if (!dirExists(dir)) {
        std::cerr << "eval dir not found: " + dir + "\n";
        return 1;
    }
    std::vector<std::string> files;
    {
        std::error_code ec;
        fs::directory_iterator it(dir, ec);
        fs::directory_iterator end;
        for (; !ec && it != end; it.increment(ec)) {
            if (ec) break;
            if (!it->is_regular_file(ec) || ec) continue;
            std::string name = it->path().filename().generic_string();
            if (name.size() >= 5 && name.compare(name.size() - 5, 5, ".json") == 0) {
                files.push_back(it->path().generic_string());
            }
        }
        if (ec) {
            std::cerr << "cannot list eval dir: " + dir + "\n";
            return 1;
        }
    }
    std::sort(files.begin(), files.end());

    struct Loaded {
        std::string path;
        EvalCase evalCase;
        bool loadOk = false;
        std::string loadErr;
    };
    std::vector<Loaded> loaded;
    for (const std::string& f : files) {
        Loaded l;
        l.path = f;
        try {
            l.evalCase = loadEvalFile(f);
            l.loadOk = true;
        } catch (const std::exception& ex) {
            l.loadErr = ex.what();
        }
        if (!filter.empty() && f.find(filter) == std::string::npos &&
            (!l.loadOk || l.evalCase.name.find(filter) == std::string::npos)) {
            continue;
        }
        loaded.push_back(l);
    }
    if (loaded.empty()) {
        std::cerr << "no evals matched" + (filter.empty() ? std::string("") : " filter '" + filter + "'") +
                         " in " + dir + "\n";
        return 1;
    }

    JsonValue root = JsonValue::makeObject();
    root.object["tool"] = JsonValue::makeString("trustgate");
    root.object["version"] = JsonValue::makeString(kTgVersion);
    JsonValue results = JsonValue::makeArray();
    int passed = 0;
    for (const Loaded& l : loaded) {
        JsonValue o = JsonValue::makeObject();
        o.object["file"] = JsonValue::makeString(l.path);
        bool ok = false;
        if (!l.loadOk) {
            o.object["name"] = JsonValue::makeString(l.path);
            o.object["passed"] = JsonValue::makeBool(false);
            JsonValue fails = JsonValue::makeArray();
            JsonValue f = JsonValue::makeObject();
            f.object["assert"] = JsonValue::makeNumber(-1.0);
            f.object["message"] = JsonValue::makeString("cannot load eval: " + l.loadErr);
            fails.array.push_back(f);
            o.object["failures"] = fails;
        } else {
            EvalResult r = runEval(l.evalCase, repo);
            ok = r.passed;
            o.object["name"] = JsonValue::makeString(l.evalCase.name);
            o.object["passed"] = JsonValue::makeBool(r.passed);
            o.object["ms"] = JsonValue::makeNumber(static_cast<double>(r.ms));
            JsonValue fails = JsonValue::makeArray();
            for (const AssertFailure& af : r.failures) {
                JsonValue f = JsonValue::makeObject();
                f.object["assert"] = JsonValue::makeNumber(static_cast<double>(af.index));
                f.object["message"] = JsonValue::makeString(af.message);
                fails.array.push_back(f);
            }
            o.object["failures"] = fails;
            appendEvalHistory(historyPath, l.evalCase.name, r.passed, r.ms);
        }
        if (ok) ++passed;
        results.array.push_back(o);
        std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] "
                  << (l.loadOk ? l.evalCase.name : l.path) << "\n";
        if (!ok) {
            const JsonValue& fails = o.at("failures");
            for (const JsonValue& f : fails.array) {
                std::cout << "    assert " << f.getNumber("assert", -1.0) << ": "
                          << f.getString("message", "") << "\n";
            }
        }
    }
    root.object["results"] = results;
    JsonValue stats = JsonValue::makeObject();
    stats.object["evals"] = JsonValue::makeNumber(static_cast<double>(loaded.size()));
    stats.object["passed"] = JsonValue::makeNumber(static_cast<double>(passed));
    stats.object["failed"] = JsonValue::makeNumber(static_cast<double>(loaded.size() - passed));
    root.object["stats"] = stats;
    bool allOk = (passed == static_cast<int>(loaded.size()));
    root.object["verdict"] = JsonValue::makeString(allOk ? "PASS" : "FAIL");

    ensureParentDir(outPath);
    if (!writeFile(outPath, toJson(root, true) + "\n")) {
        std::cerr << "cannot write results file: " + outPath + "\n";
        return 1;
    }
    std::cout << "eval: " << (allOk ? "PASS" : "FAIL") << " (" << passed << "/"
              << loaded.size() << " -> " << outPath << ")\n";
    return allOk ? 0 : 2;
}

}  // namespace tg
