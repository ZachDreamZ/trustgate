#pragma once

// Quarantine model + history scoring.
// Quarantine file supports two formats:
//   1. YAML subset exactly as written by writeQuarantineYaml.
//   2. JSON {"quarantined":[{id,flake_rate,runs,ttl_days,reason,
//      category,confidence,signals[]}] matters (missing keys default).
// History file is JSONL: {"ts":"...","results":{"TestId":{"s":"P"|"F"|"S",
// "m":"failure excerpt","t":ms}}}. Legacy lines with bare "P"/"F"/"S"
// string values still read.

#include <string>
#include <vector>

namespace tg {

struct QuarantineEntry {
    std::string id;
    double flakeRate = 0.0;
    int runs = 0;
    int ttlDays = 14;
    std::string reason;
    std::string category = "unknown";
    double confidence = 0.0;
    std::vector<std::string> signals;
};

// One test outcome from the run being recorded.
struct FlakeSample {
    std::string id;
    char status = 'P';  // 'P' | 'F' | 'S'
    std::string message;  // failure excerpt (only when status == 'F')
    double timeMs = 0.0;
};

struct FlakeOptions {
    int minRuns = 3;
    int maxRuns = 500;
    int ttlDays = 14;
};

// Appends one run to historyPath (truncating to maxRuns), scores every test
// seen in history, classifies each flaky test's most recent failure, and
// returns the entries that qualify for quarantine.
std::vector<QuarantineEntry> updateFlakeHistory(
    const std::string& historyPath,
    const std::vector<FlakeSample>& runResults,
    const FlakeOptions& opts,
    std::string& error);

void writeQuarantineYaml(const std::string& path,
                         const std::vector<QuarantineEntry>& entries);

// Never throws: returns empty list on missing/unparseable file.
std::vector<QuarantineEntry> loadQuarantine(const std::string& path);

bool isQuarantined(const std::vector<QuarantineEntry>& list, const std::string& id);

}  // namespace tg
