#pragma once

// File IO + hashing utilities. v0.1 uses FNV-1a-64 (fast, stdlib-only).
// Upgrade path (no API change for callers of fileIdentity): BLAKE3.

#include <cstdint>
#include <string>
#include <vector>

namespace tg {

bool fileExists(const std::string& path);
bool dirExists(const std::string& path);

// Throws std::runtime_error on failure.
std::string readFile(const std::string& path);
bool writeFile(const std::string& path, const std::string& data);

uint64_t fnv1a64(const void* data, std::size_t len);
inline uint64_t fnv1a64(const std::string& s) {
    return fnv1a64(s.data(), s.size());
}
uint64_t hashCombine(uint64_t a, uint64_t b);
std::string toHex16(uint64_t v);
uint64_t fileSize(const std::string& path);

// "YYYY-MM-DDTHH:MM:SSZ" (UTC). Returns "" on failure (never throws).
std::string utcNowIso();

// Creates parent directories of path (no-op when none). Returns false on error.
bool ensureParentDir(const std::string& path);

// Counts '\n'-terminated lines; a trailing partial line counts as one.
// Returns -1 when the file cannot be read.
long countFileLines(const std::string& path);

}  // namespace tg
