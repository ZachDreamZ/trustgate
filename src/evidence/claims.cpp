#include "evidence/claims.h"

#include <cctype>
#include <stdexcept>

#include "core/fsutil.h"
#include "core/json.h"

namespace tg {

std::vector<Claim> loadClaims(const std::string& path) {
    std::vector<Claim> out;
    JsonValue root = parseJson(readFile(path));  // may throw
    if (!root.isObject() || !root.has("claims")) {
        throw std::runtime_error("claims file must be an object with a 'claims' array");
    }
    const JsonValue& arr = root.at("claims");
    if (!arr.isArray()) throw std::runtime_error("'claims' must be an array");
    for (const JsonValue& item : arr.array) {
        if (!item.isObject()) throw std::runtime_error("each claim must be an object");
        Claim c;
        c.id = item.getString("id", "");
        c.text = item.getString("text", "");
        if (c.id.empty()) throw std::runtime_error("claim is missing required 'id'");
        auto getStrArray = [&](const char* key, std::vector<std::string>& dst) {
            if (!item.has(key)) return;
            const JsonValue& v = item.at(key);
            if (!v.isArray()) throw std::runtime_error(std::string("'") + key + "' must be an array");
            for (const JsonValue& e : v.array) {
                if (!e.isString()) {
                    throw std::runtime_error(std::string("'") + key + "' entries must be strings");
                }
                dst.push_back(e.str);
            }
        };
        getStrArray("files", c.files);
        getStrArray("tests", c.tests);
        getStrArray("artifacts", c.artifacts);
        out.push_back(c);
    }
    return out;
}

namespace {

bool isRangeSuffix(const std::string& s) {
    if (s.empty()) return false;
    bool dashSeen = false;
    for (char c : s) {
        if (c == '-') {
            if (dashSeen) return false;
            dashSeen = true;
        } else if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return std::isdigit(static_cast<unsigned char>(s.back())) != 0;
}

}  // namespace

bool parseFileRef(const std::string& s, FileRef& out) {
    out = FileRef();
    if (s.empty()) return false;
    std::string::size_type colon = s.find_last_of(':');
    if (colon == std::string::npos) {
        out.path = s;
        return true;
    }
    std::string suffix = s.substr(colon + 1);
    if (!isRangeSuffix(suffix)) {
        // Covers "C:\..." drive-letter colons and plain paths.
        out.path = s;
        return true;
    }
    out.path = s.substr(0, colon);
    if (out.path.empty()) return false;
    out.hasRange = true;
    std::string::size_type dash = suffix.find('-');
    try {
        if (dash == std::string::npos) {
            out.start = std::stol(suffix);
            out.end = out.start;
        } else {
            out.start = std::stol(suffix.substr(0, dash));
            out.end = std::stol(suffix.substr(dash + 1));
        }
    } catch (...) {
        return false;
    }
    if (out.start <= 0 || out.end < out.start) return false;
    return true;
}

}  // namespace tg
