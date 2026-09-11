#pragma once

// AI claims model + file-reference grammar.
// claims.json: {"claims":[{"id","text","files":[],"tests":[],"artifacts":[]}]}
// File ref grammar: "path[:start[-end]]" where the split uses the LAST ':'
// only when the suffix matches ^\d+(-\d+)?$ (Windows drive letters safe).

#include <string>
#include <vector>

namespace tg {

struct Claim {
    std::string id;
    std::string text;
    std::vector<std::string> files;
    std::vector<std::string> tests;
    std::vector<std::string> artifacts;
};

// Throws std::runtime_error / JsonError on failure.
std::vector<Claim> loadClaims(const std::string& path);

struct FileRef {
    std::string path;
    long start = 0;
    long end = 0;
    bool hasRange = false;
};

bool parseFileRef(const std::string& s, FileRef& out);

}  // namespace tg
