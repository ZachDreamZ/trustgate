#include "flake/quarantine.h"

#include <cstdlib>
#include <map>
#include <sstream>

#include "core/fsutil.h"
#include "core/json.h"
#include "flake/category.h"

namespace tg {
namespace {

std::string trim(const std::string& s) {
    std::string::size_type a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    std::string::size_type b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string unquote(const std::string& s) {
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

// Parses the exact YAML shape written by writeQuarantineYaml.
// Tolerates blank lines and comments; anything else is ignored.
std::vector<QuarantineEntry> parseQuarantineYaml(const std::string& text) {
    std::vector<QuarantineEntry> out;
    std::istringstream in(text);
    std::string line;
    QuarantineEntry cur;
    bool inItem = false;
    auto flush = [&]() {
        if (inItem && !cur.id.empty()) out.push_back(cur);
        cur = QuarantineEntry();
        inItem = false;
    };
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        if (t.rfind("- id:", 0) == 0) {
            flush();
            inItem = true;
            cur.id = unquote(trim(t.substr(5)));
        } else if (inItem) {
            std::string::size_type c = t.find(':');
            if (c == std::string::npos) continue;
            std::string key = trim(t.substr(0, c));
            std::string val = unquote(trim(t.substr(c + 1)));
            if (key == "flake_rate") {
                cur.flakeRate = std::strtod(val.c_str(), nullptr);
            } else if (key == "runs") {
                cur.runs = std::atoi(val.c_str());
            } else if (key == "ttl_days") {
                cur.ttlDays = std::atoi(val.c_str());
            } else if (key == "reason") {
                cur.reason = val;
            } else if (key == "category") {
                cur.category = val;
            } else if (key == "confidence") {
                cur.confidence = std::strtod(val.c_str(), nullptr);
            } else if (key == "signals") {
                cur.signals.clear();
                std::istringstream parts(val);
                std::string part;
                while (std::getline(parts, part, ',')) {
                    part = trim(part);
                    if (!part.empty()) cur.signals.push_back(part);
                }
            }
        }
    }
    flush();
    return out;
}

std::vector<QuarantineEntry> parseQuarantineJson(const std::string& text) {
    std::vector<QuarantineEntry> out;
    JsonValue root = parseJson(text);  // may throw; caller guards
    if (!root.isObject() || !root.has("quarantined")) return out;
    const JsonValue& arr = root.at("quarantined");
    if (!arr.isArray()) return out;
    for (const JsonValue& item : arr.array) {
        if (!item.isObject()) continue;
        QuarantineEntry e;
        e.id = item.getString("id", "");
        if (e.id.empty()) continue;
        e.flakeRate = item.getNumber("flake_rate", 0.0);
        e.runs = static_cast<int>(item.getNumber("runs", 0.0));
        e.ttlDays = static_cast<int>(item.getNumber("ttl_days", 14.0));
        e.reason = item.getString("reason", "");
        e.category = item.getString("category", "unknown");
        e.confidence = item.getNumber("confidence", 0.0);
        if (item.has("signals") && item.at("signals").isArray()) {
            for (const JsonValue& s : item.at("signals").array) {
                if (s.isString() && !s.str.empty()) e.signals.push_back(s.str);
            }
        }
        out.push_back(e);
    }
    return out;
}

}  // namespace

std::vector<QuarantineEntry> updateFlakeHistory(
    const std::string& historyPath,
    const std::vector<FlakeSample>& runResults,
    const FlakeOptions& opts,
    std::string& error) {
    error.clear();
    std::vector<std::string> lines;
    if (fileExists(historyPath)) {
        try {
            std::string text = readFile(historyPath);
            std::istringstream in(text);
            std::string line;
            while (std::getline(in, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!trim(line).empty()) lines.push_back(line);
            }
        } catch (const std::exception& ex) {
            error = std::string("cannot read history file: ") + ex.what();
            return {};
        }
    }

    JsonValue run = JsonValue::makeObject();
    run.object["ts"] = JsonValue::makeString(utcNowIso());
    JsonValue results = JsonValue::makeObject();
    for (const FlakeSample& sample : runResults) {
        JsonValue entry = JsonValue::makeObject();
        entry.object["s"] = JsonValue::makeString(std::string(1, sample.status));
        entry.object["t"] = JsonValue::makeNumber(sample.timeMs);
        if (sample.status == 'F' && !sample.message.empty()) {
            entry.object["m"] = JsonValue::makeString(sample.message.substr(0, 200));
        }
        results.object[sample.id] = entry;
    }
    run.object["results"] = results;
    lines.push_back(toJson(run));

    while (static_cast<int>(lines.size()) > opts.maxRuns) {
        lines.erase(lines.begin());
    }
    {
        std::string out;
        for (const std::string& l : lines) {
            out += l;
            out += "\n";
        }
        ensureParentDir(historyPath);  // best effort; writeFile reports failure
        if (!writeFile(historyPath, out)) {
            error = "cannot write history file: " + historyPath;
            return {};
        }
    }

    // Score: aggregate pass/fail counts per test over retained runs, tracking
    // the most recent failure evidence for classification. Accepts legacy
    // history lines whose values are bare "P"/"F"/"S" strings.
    std::map<std::string, int> fails;
    std::map<std::string, int> totals;
    std::map<std::string, std::string> lastFailMsg;
    for (const std::string& l : lines) {
        try {
            JsonValue r = parseJson(l);
            if (!r.isObject() || !r.has("results")) continue;
            const JsonValue& res = r.at("results");
            if (!res.isObject()) continue;
            for (const auto& kv : res.object) {
                std::string status;
                std::string msg;
                if (kv.second.isString()) {
                    status = kv.second.str;  // legacy format
                } else if (kv.second.isObject()) {
                    status = kv.second.getString("s", "");
                    msg = kv.second.getString("m", "");
                } else {
                    continue;
                }
                totals[kv.first]++;
                if (status == "F") {
                    fails[kv.first]++;
                    if (!msg.empty()) lastFailMsg[kv.first] = msg;
                }
            }
        } catch (const JsonError&) {
            continue;  // skip corrupt lines
        }
    }

    std::vector<QuarantineEntry> quarantined;
    for (const auto& kv : totals) {
        int n = kv.second;
        int f = fails[kv.first];
        if (n < opts.minRuns) continue;
        if (f == 0 || f == n) continue;  // consistently passing/failing != flaky
        QuarantineEntry e;
        e.id = kv.first;
        e.runs = n;
        e.flakeRate = static_cast<double>(f) / static_cast<double>(n);
        e.ttlDays = opts.ttlDays;
        Cause cause = classifyFailure(lastFailMsg[kv.first], e.flakeRate);
        e.category = cause.category;
        e.confidence = cause.confidence;
        e.signals = cause.signals;
        std::ostringstream reason;
        reason << "flaky-" << e.category << ": " << f << " failures in last " << n << " runs";
        e.reason = reason.str();
        quarantined.push_back(e);
    }
    return quarantined;
}

void writeQuarantineYaml(const std::string& path,
                         const std::vector<QuarantineEntry>& entries) {
    std::ostringstream out;
    out << "# Generated by `tg flake`. Do not hand-edit; re-run `tg flake`.\n";
    out << "version: 1\n";
    out << "quarantined:\n";
    if (entries.empty()) {
        out << "  []\n";
    }
    for (const QuarantineEntry& e : entries) {
        out << "  - id: " << e.id << "\n";
        out << "    flake_rate: " << e.flakeRate << "\n";
        out << "    runs: " << e.runs << "\n";
        out << "    ttl_days: " << e.ttlDays << "\n";
        out << "    reason: \"" << e.reason << "\"\n";
        out << "    category: " << e.category << "\n";
        out << "    confidence: " << e.confidence << "\n";
        out << "    signals: \"";
        for (std::size_t i = 0; i < e.signals.size(); ++i) {
            if (i > 0) out << ", ";
            out << e.signals[i];
        }
        out << "\"\n";
    }
    writeFile(path, out.str());
}

std::vector<QuarantineEntry> loadQuarantine(const std::string& path) {
    std::vector<QuarantineEntry> empty;
    if (!fileExists(path)) return empty;
    std::string text;
    try {
        text = readFile(path);
    } catch (...) {
        return empty;
    }
    std::string t = trim(text);
    if (t.empty()) return empty;
    try {
        if (t[0] == '{') return parseQuarantineJson(text);
        return parseQuarantineYaml(text);
    } catch (...) {
        return empty;
    }
}

bool isQuarantined(const std::vector<QuarantineEntry>& list, const std::string& id) {
    for (const QuarantineEntry& e : list) {
        if (e.id == id) return true;
    }
    return false;
}

}  // namespace tg
