#pragma once

// Heuristic root-cause classifier for flaky-test failures.
// Message-driven keyword rules evaluated in priority order; matching is
// case-insensitive with word boundaries ("oom" must not match "room").
// Deterministic: same input always yields the same category.

#include <string>
#include <vector>

namespace tg {

struct Cause {
    // timeout | race | network | resource | ordering | assertion | unknown
    std::string category = "unknown";
    double confidence = 0.0;  // 0..1
    std::vector<std::string> signals;  // matched keywords, as listed below
};

// message: failure excerpt (any case). flakeRate: historical fail rate 0..1;
// a first-seen failure (rate 0) caps confidence since evidence is thin.
Cause classifyFailure(const std::string& message, double flakeRate);

}  // namespace tg
