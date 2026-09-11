#include "flake/category.h"

#include <cctype>

namespace tg {
namespace {

struct Rule {
    const char* category;
    const char* keywords[10];
};

const Rule kRules[] = {
    {"timeout",
     {"timed out", "timeout", "deadline exceeded", "exceeded time limit", "did not complete in",
      "killed after", "wait_for", "waited more than", nullptr, nullptr}},
    {"race",
     {"address already in use", "eaddrinuse", "already in use", "bind failed", "already bound",
      "deadlock", "data race", "race condition", nullptr, nullptr}},
    {"network",
     {"connection refused", "connection reset", "econnrefused", "econnreset", "no such host",
      "getaddrinfo", "name resolution", "network is unreachable", "broken pipe", "socket hang up"}},
    {"network",
     {"bad gateway", "service unavailable", " 502", " 503", " 504", "http 502", "http 503",
      "http 504", nullptr, nullptr}},
    {"resource",
     {"out of memory", "outofmemory", "memoryerror", "enospc", "no space left",
      "too many open files", "emfile", "disk quota", "no space", "oom"}},
    {"ordering",
     {"passes in isolation", "passes alone", "when run after", "test order", "order depend",
      "test pollution", "polluted", "did not clean", "left over", "isolation"}},
    {"assertion",
     {"assertion", "assert", "expected", "actual", "expect", "mismatch", "not equal", "to equal",
      "should be", "to be"}},
};

std::string lowerOf(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

bool isWordChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

// True when needle occurs with non-word characters (or edges) on both sides.
bool containsWord(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return false;
    std::string::size_type pos = 0;
    while (true) {
        pos = haystack.find(needle, pos);
        if (pos == std::string::npos) return false;
        bool leftOk = (pos == 0) || !isWordChar(haystack[pos - 1]);
        std::string::size_type end = pos + needle.size();
        bool rightOk = (end >= haystack.size()) || !isWordChar(haystack[end]);
        if (leftOk && rightOk) return true;
        pos += 1;
    }
}

}  // namespace

Cause classifyFailure(const std::string& message, double flakeRate) {
    Cause cause;
    std::string text = lowerOf(message);
    for (const Rule& rule : kRules) {
        std::vector<std::string> hits;
        for (const char* kw : rule.keywords) {
            if (kw == nullptr) break;
            if (containsWord(text, kw)) hits.push_back(kw);
        }
        if (!hits.empty()) {
            cause.category = rule.category;
            cause.signals = hits;
            cause.confidence = 0.6 + 0.15 * static_cast<double>(hits.size() - 1);
            if (cause.confidence > 0.9) cause.confidence = 0.9;
            if (flakeRate <= 0.0 && cause.confidence > 0.5) {
                cause.confidence = 0.5;  // single sample: thin evidence
            }
            return cause;
        }
    }
    return cause;  // unknown, confidence 0
}

}  // namespace tg
