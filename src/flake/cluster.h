#pragma once

// Systemic flakiness: tests that fail TOGETHER across runs usually share one
// root cause (intermittent infra, shared fixture, ordering). This module
// groups flaky tests by failure co-occurrence (Jaccard similarity over the
// runs where each test failed) and attributes one suspected cause per group
// by majority vote of the members' classified last failures.
// Deterministic: sorted output, alphabetical tie-breaks.

#include <string>
#include <vector>

namespace tg {

struct Cluster {
    std::vector<std::string> members;  // sorted test ids
    int runsTogether = 0;  // runs where ALL members failed
    int runsTotal = 0;     // runs where ANY member failed (union)
    std::string cause = "unknown";
    double confidence = 0.0;  // mean member confidence
};

// lines: raw history JSONL lines (same format updateFlakeHistory reads).
// minSim: Jaccard threshold in (0,1]; minFailures: a test needs at least this
// many failures to be clustered (default 2: co-occurrence needs evidence).
std::vector<Cluster> computeClusters(const std::vector<std::string>& lines, double minSim,
                                     int minFailures = 2);

}  // namespace tg
