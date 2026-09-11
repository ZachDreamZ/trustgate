#include "core/fsutil.h"

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace tg {
namespace fs = std::filesystem;

bool fileExists(const std::string& path) {
    std::error_code ec;
    return fs::is_regular_file(path, ec);
}

bool dirExists(const std::string& path) {
    std::error_code ec;
    return fs::is_directory(path, ec);
}

std::string readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open file for reading: " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    if (in.bad()) throw std::runtime_error("error while reading file: " + path);
    return ss.str();
}

bool writeFile(const std::string& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();
    return static_cast<bool>(out);
}

uint64_t fnv1a64(const void* data, std::size_t len) {
    const unsigned char* p = static_cast<const unsigned char*>(data);
    uint64_t h = 14695981039346656037ULL;
    for (std::size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(p[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

uint64_t hashCombine(uint64_t a, uint64_t b) {
    // SplitMix64-style mix of b into a.
    uint64_t z = b + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return a ^ (z ^ (z >> 31));
}

std::string toHex16(uint64_t v) {
    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << v;
    return oss.str();
}

uint64_t fileSize(const std::string& path) {
    std::error_code ec;
    uint64_t n = fs::file_size(path, ec);
    return ec ? 0 : n;
}

std::string utcNowIso() {
    std::time_t t = std::time(nullptr);
    if (t == static_cast<std::time_t>(-1)) return "";
    std::tm tmv{};
#if defined(_WIN32)
    if (gmtime_s(&tmv, &t) != 0) return "";
#else
    if (gmtime_r(&t, &tmv) == nullptr) return "";
#endif
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0) return "";
    return std::string(buf);
}

long countFileLines(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return -1;
    long lines = 0;
    bool any = false;
    bool endsWithNewline = true;
    char c;
    while (in.get(c)) {
        any = true;
        if (c == '\n') {
            ++lines;
            endsWithNewline = true;
        } else {
            endsWithNewline = false;
        }
    }
    if (any && !endsWithNewline) ++lines;
    return lines;
}

bool ensureParentDir(const std::string& path) {
    std::string::size_type sep = path.find_last_of("/\\");
    if (sep == std::string::npos) return true;
    std::error_code ec;
    fs::create_directories(path.substr(0, sep), ec);
    return !ec;
}

}  // namespace tg
