#pragma once

// Environment reproducibility fingerprint.
// Walks a directory (sorted, deterministic), hashing relative path + size +
// contents with SHA-256, plus toolchain probes and selected env vars. Excludes
// volatile state (.git, build outputs, .trustgate run outputs) so the ID is
// stable across runs.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "core/json.h"

namespace tg {

struct FileEntry {
    std::string path;  // relative, '/' separators
    uint64_t size = 0;
    std::string hash;  // 64 lowercase hex chars (SHA-256)
};

struct Fingerprint {
    int formatVersion = 2;
    std::string hashAlgorithm = "sha256";
    std::string id;  // 64 lowercase hex chars (SHA-256)
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
    // Probe git/cmake versions into toolchain (costs ~2 process spawns).
    // Note: disabling changes the fingerprint ID (toolchain section empties).
    bool probeToolchain = true;
    // File-hash cache (size+mtime validated). Empty cachePath disables.
    bool useCache = true;
    std::string cachePath;
};

struct FingerprintResult {
    Fingerprint fp;
    std::vector<std::string> warnings;
    int skipped = 0;
    // Up to kMaxSkipPaths reported skip paths (UTF-8 rel paths); the count
    // above is authoritative. Skips happen on unreadable entries and, on
    // Windows, paths hitting the 260-char MAX_PATH limit — always surfaced,
    // never silent, so coverage gaps cannot hide.
    std::vector<std::string> skippedPaths;
};

const std::size_t kMaxSkipPaths = 50;

FingerprintResult computeFingerprint(const FingerprintOptions& opts);

JsonValue fingerprintToJson(const Fingerprint& fp);
// Throws JsonError / std::runtime_error on invalid or unsupported input.
// Legacy v1 (FNV-1a-64) fingerprints are rejected explicitly; recompute them
// with a current TrustGate binary rather than silently reinterpreting hashes.
Fingerprint fingerprintFromJson(const JsonValue& v);

struct FpDiff {
    std::vector<std::string> added;
    std::vector<std::string> removed;
    std::vector<std::string> changed;
};

FpDiff diffFingerprints(const Fingerprint& oldFp, const Fingerprint& newFp);

}  // namespace tg
