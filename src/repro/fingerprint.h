#pragma once

// Environment reproducibility fingerprint.
// Walks a directory (sorted, deterministic), hashing relative path + size +
// contents (FNV-1a-64 v0.1; BLAKE3 upgrade path), plus toolchain probes and
// selected env vars. Excludes volatile state (.git, build outputs,
// .trustgate run outputs) so the ID is stable across runs.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "core/json.h"

namespace tg {

struct FileEntry {
    std::string path;  // relative, '/' separators
    uint64_t size = 0;
    uint64_t hash = 0;
};

struct Fingerprint {
    std::string id;  // 16 hex chars
    std::string os;
    std::string created;
    std::vector<FileEntry> files;
    std::map<std::string, std::string> toolchain;
    std::map<std::string, std::string> env;
};

struct FingerprintOptions {
    std::string root = ".";
    std::vector<std::string> envNames;
    // Exact basenames excluded (e.g. the --out file when it lives in root).
    std::vector<std::string> excludeFilenames;
};

struct FingerprintResult {
    Fingerprint fp;
    std::vector<std::string> warnings;
    int skipped = 0;
};

FingerprintResult computeFingerprint(const FingerprintOptions& opts);

JsonValue fingerprintToJson(const Fingerprint& fp);
// Throws JsonError / std::runtime_error on invalid input.
Fingerprint fingerprintFromJson(const JsonValue& v);

struct FpDiff {
    std::vector<std::string> added;
    std::vector<std::string> removed;
    std::vector<std::string> changed;
};

FpDiff diffFingerprints(const Fingerprint& oldFp, const Fingerprint& newFp);

}  // namespace tg
