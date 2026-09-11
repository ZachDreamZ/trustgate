#pragma once

// Quarantine model + history scoring.
// Quarantine file supports two formats:
//   1. YAML subset exactly as written by writeQuarantineYaml.
//   2. JSON {"quarantined":[{id,flake_rate,runs,ttl_days,reason}]}.
// History file is JSONL: {"ts":"...","results":{"TestId":"P"|"F"|"S"}}.

#include <string>
#include <vector>

namespace tg {

struct QuarantineEntry {
    std::string id;
    double flakeRate = 0.0;
    int runs = 0;
    int ttlDays = 14;
    std::string reason;
};

struct FlakeOptions {
    int minRuns = 3;
    int maxRuns = 500;
    int ttlDays = 14;
};

// Appends one run to historyPath (truncating to maxRuns), scores every test
// seen in history, and returns the entries that qualify for quarantine.
std::vector<QuarantineEntry> updateFlakeHistory(
    const std::string& historyPath,
    const std::vector<std::pair<std::string, char>>& runResults,
    const FlakeOptions& opts,
    std::string& error);

void writeQuarantineYaml(const std::string& path,
                         const std::vector<QuarantineEntry>& entries);

// Never throws: returns empty list on missing/unparseable file.
std::vector<QuarantineEntry> loadQuarantine(const std::string& path);

bool isQuarantined(const std::vector<QuarantineEntry>& list, const std::string& id);

}  // namespace tg
