#include "repro/fingerprint.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <tuple>

#include "attest/sha256.h"
#include "core/fsutil.h"
#include "core/json.h"
#include "core/mmap.h"
#include "core/proc.h"

namespace tg {
namespace fs = std::filesystem;

namespace {

const char* kIgnoreDirs[] = {
    ".git", "build", "out", "node_modules", ".vs", ".trustgate",
    "CMakeFiles", "_deps", ".hg", ".svn", "__pycache__", ".pytest_cache",
    "target", "bin", "obj",
};

bool isIgnoredDir(const std::string& name) {
    for (const char* d : kIgnoreDirs) {
        if (name == d) return true;
    }
    return false;
}

bool isExcludedFile(const std::string& basename,
                    const std::vector<std::string>& exclude) {
    for (const std::string& e : exclude) {
        if (basename == e) return true;
    }
    return false;
}

std::string osName() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

std::string digestHex(const std::array<uint8_t, 32>& digest) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(64);
    for (std::size_t i = 0; i < digest.size(); ++i) {
        out[i * 2] = kHex[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = kHex[digest[i] & 0x0f];
    }
    return out;
}

std::string sha256Hex(const void* data, std::size_t len) {
    return digestHex(sha256(data, len));
}

std::string sha256Hex(const std::string& data) {
    return sha256Hex(data.data(), data.size());
}

bool isSha256Hex(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

void appendCanonicalField(std::string& out, const std::string& name,
                          const std::string& value) {
    out += std::to_string(name.size());
    out.push_back(':');
    out += name;
    out.push_back('=');
    out += std::to_string(value.size());
    out.push_back(':');
    out += value;
    out.push_back('\n');
}

// Hash-cache helpers. Entries are keyed by relative path; a hit requires an
// exact (size, mtime-ticks) match, mtime stored as a decimal string (JSON
// doubles cannot hold 64-bit timestamps exactly; values may be negative).
// Corrupt/version-mismatched caches start fresh; cache I/O never fails a run.

const char* kCacheAlgo = "sha256-1";
const double kCacheVersion = 2.0;

using CacheMap =
    std::map<std::string, std::tuple<uint64_t, long long, std::string>>;

CacheMap loadHashCache(const std::string& path) {
    CacheMap out;
    if (!fileExists(path)) return out;
    try {
        JsonValue root = parseJson(readFile(path));
        if (!root.isObject()) return out;
        if (root.getNumber("version", 0.0) != kCacheVersion) return out;
        if (root.getString("algo", "") != kCacheAlgo) return out;
        if (!root.has("entries")) return out;
        const JsonValue& entries = root.at("entries");
        if (!entries.isObject()) return out;
        for (const auto& kv : entries.object) {
            if (!kv.second.isObject()) continue;
            double sizeNum = kv.second.getNumber("size", -1.0);
            std::string mtimeStr = kv.second.getString("mtime_ticks", "");
            std::string hex = kv.second.getString("hash", "");
            if (sizeNum < 0.0 || sizeNum > 9.0e15 || mtimeStr.empty() ||
                !isSha256Hex(hex)) {
                continue;
            }
            char* end = nullptr;
            long long mtime = std::strtoll(mtimeStr.c_str(), &end, 10);
            if (end == nullptr || *end != '\0') continue;
            std::transform(hex.begin(), hex.end(), hex.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            out[kv.first] =
                std::make_tuple(static_cast<uint64_t>(sizeNum), mtime, hex);
        }
    } catch (...) {
        // Corrupt cache starts fresh.
    }
    return out;
}

bool saveHashCache(const std::string& path, const CacheMap& cache) {
    JsonValue root = JsonValue::makeObject();
    root.object["version"] = JsonValue::makeNumber(kCacheVersion);
    root.object["algo"] = JsonValue::makeString(kCacheAlgo);
    JsonValue entries = JsonValue::makeObject();
    for (const auto& kv : cache) {
        JsonValue e = JsonValue::makeObject();
        e.object["size"] =
            JsonValue::makeNumber(static_cast<double>(std::get<0>(kv.second)));
        e.object["mtime_ticks"] =
            JsonValue::makeString(std::to_string(std::get<1>(kv.second)));
        e.object["hash"] = JsonValue::makeString(std::get<2>(kv.second));
        entries.object[kv.first] = e;
    }
    root.object["entries"] = entries;
    ensureParentDir(path);
    std::string tmp = path + ".tmp";
    if (!writeFile(tmp, toJson(root))) return false;
    std::error_code ec;
#if defined(_WIN32)
    fs::remove(pathFromUtf8(path), ec);
    ec.clear();
#endif
    fs::rename(pathFromUtf8(tmp), pathFromUtf8(path), ec);
    return !ec;
}

}  // namespace

FingerprintResult computeFingerprint(const FingerprintOptions& opts) {
    FingerprintResult result;
    Fingerprint& fp = result.fp;
    fp.formatVersion = 2;
    fp.hashAlgorithm = "sha256";
    fp.os = osName();
    fp.created = utcNowIso();

    struct Target {
        std::string rel;   // relative, '/' separators
        std::string full;  // UTF-8 path for reading
        uint64_t size = 0;
        // Opaque file_clock ticks. The epoch is implementation-defined and
        // the value may even be negative; only equality across runs matters.
        long long mtimeTicks = 0;
        bool haveStat = false;
    };

    std::vector<Target> targets;
    std::error_code ec;
    fs::path rootPath = pathFromUtf8(opts.root);
    if (!fs::exists(rootPath, ec)) {
        result.warnings.push_back("root does not exist: " + opts.root);
    } else {
        fs::recursive_directory_iterator it(
            rootPath, fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;
        auto noteSkip = [&](const std::string& display) {
            ++result.skipped;
            if (!display.empty() && result.skippedPaths.size() < kMaxSkipPaths) {
                result.skippedPaths.push_back(display);
            }
        };
        for (; !ec && it != end; it.increment(ec)) {
            if (ec) {
                noteSkip("");
                ec.clear();
                continue;
            }
            const fs::path& p = it->path();
            std::string name = pathToUtf8(p.filename());
            if (it->is_directory(ec)) {
                if (!ec && isIgnoredDir(name)) it.disable_recursion_pending();
                continue;
            }
            if (ec) {
                noteSkip(pathToUtf8(p));
                ec.clear();
                continue;
            }
            if (!it->is_regular_file(ec) || ec) {
                noteSkip(pathToUtf8(p));
                ec.clear();
                continue;
            }
            if (isExcludedFile(name, opts.excludeFilenames)) continue;
            std::error_code relEc;
            fs::path rel = fs::relative(p, rootPath, relEc);
            if (relEc) {
                noteSkip(pathToUtf8(p));
                continue;
            }
            Target t;
            t.rel = pathToUtf8(rel);
            t.full = pathToUtf8(p);
            std::error_code szEc, tmEc;
            t.size = it->file_size(szEc);
            if (szEc) t.size = 0;
            auto ft = it->last_write_time(tmEc);
            if (!tmEc) {
                using ticks100ns =
                    std::chrono::duration<long long, std::ratio<1, 10000000>>;
                t.mtimeTicks =
                    std::chrono::duration_cast<ticks100ns>(ft.time_since_epoch())
                        .count();
                t.haveStat = true;
            }
            targets.push_back(t);
        }
    }
    std::sort(targets.begin(), targets.end(),
              [](const Target& a, const Target& b) { return a.rel < b.rel; });

    CacheMap cache;
    bool cacheUsable = opts.useCache && !opts.cachePath.empty();
    if (cacheUsable) cache = loadHashCache(opts.cachePath);

    // Hash contents with a portable std::thread pool. Each file is independent;
    // results land by index and are mixed into the canonical ID in sorted order.
    std::vector<FileEntry> hashed(targets.size());
    std::vector<char> ready(targets.size(), 0);
    std::vector<char> fromCache(targets.size(), 0);
    std::atomic<std::size_t> next{0};
    std::atomic<int> skippedCount{result.skipped};
    std::mutex skipMutex;
    unsigned hw = std::thread::hardware_concurrency();
    unsigned workers = 1;
    if (targets.size() >= 64) {
        workers = (hw == 0) ? 4 : hw;
        if (workers < 2) workers = 2;
        if (workers > 16) workers = 16;
        if (workers > static_cast<unsigned>(targets.size())) {
            workers = static_cast<unsigned>(targets.size());
        }
    }

    auto hashWorker = [&]() {
        while (true) {
            std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= targets.size()) break;
            const Target& t = targets[i];
            if (t.haveStat) {
                auto cit = cache.find(t.rel);
                if (cit != cache.end() && std::get<0>(cit->second) == t.size &&
                    std::get<1>(cit->second) == t.mtimeTicks) {
                    hashed[i].path = t.rel;
                    hashed[i].size = t.size;
                    hashed[i].hash = std::get<2>(cit->second);
                    ready[i] = 1;
                    fromCache[i] = 1;
                    continue;
                }
            }

            MappedFile mf;
            if (mf.map(t.full)) {
                hashed[i].path = t.rel;
                hashed[i].size = static_cast<uint64_t>(mf.size());
                hashed[i].hash = sha256Hex(mf.data(), mf.size());
                ready[i] = 1;
            } else {
                try {
                    std::string data = readFile(t.full);
                    hashed[i].path = t.rel;
                    hashed[i].size = static_cast<uint64_t>(data.size());
                    hashed[i].hash = sha256Hex(data);
                    ready[i] = 1;
                } catch (...) {
                    skippedCount.fetch_add(1, std::memory_order_relaxed);
                    std::lock_guard<std::mutex> lock(skipMutex);
                    if (result.skippedPaths.size() < kMaxSkipPaths) {
                        result.skippedPaths.push_back(t.rel);
                    }
                }
            }
        }
    };

    if (workers == 1) {
        hashWorker();
    } else {
        std::vector<std::thread> pool;
        for (unsigned w = 0; w < workers; ++w) pool.emplace_back(hashWorker);
        for (std::thread& t : pool) t.join();
    }

    for (std::size_t i = 0; i < hashed.size(); ++i) {
        if (ready[i]) fp.files.push_back(hashed[i]);
    }
    result.skipped = skippedCount.load();

    if (cacheUsable) {
        CacheMap fresh;
        for (std::size_t i = 0; i < hashed.size(); ++i) {
            if (ready[i] && targets[i].haveStat) {
                fresh[targets[i].rel] = std::make_tuple(
                    hashed[i].size, targets[i].mtimeTicks, hashed[i].hash);
            }
        }
        if (!saveHashCache(opts.cachePath, fresh)) {
            result.warnings.push_back("cannot write hash cache: " + opts.cachePath);
        } else {
            int hits = 0;
            for (char c : fromCache) hits += c;
            if (hits > 0) {
                std::ostringstream note;
                note << "hash cache: " << hits << "/" << targets.size()
                     << " reused";
                result.warnings.push_back(note.str());
            }
        }
    }

    if (opts.probeToolchain) {
        std::string git = probeFirstLine("git --version");
        if (!git.empty()) fp.toolchain["git"] = git;
        std::string cmake = probeFirstLine("cmake --version");
        if (!cmake.empty()) {
            std::string::size_type nl = cmake.find_first_of("\r\n");
            fp.toolchain["cmake"] =
                (nl == std::string::npos) ? cmake : cmake.substr(0, nl);
        }
    }

    for (const std::string& name : opts.envNames) {
        const char* val = std::getenv(name.c_str());
        if (val != nullptr) {
            fp.env[name] = val;
        } else {
            result.warnings.push_back("env var not set: " + name);
        }
    }

    // Canonical v2 ID: explicit length-prefixing removes concatenation
    // ambiguity. `os` and `created` stay metadata (as in v1) so identical
    // inputs with --no-probe produce the same ID across platforms and runs.
    std::string canonical;
    appendCanonicalField(canonical, "format", "2");
    appendCanonicalField(canonical, "hash_algorithm", fp.hashAlgorithm);
    for (const FileEntry& e : fp.files) {
        appendCanonicalField(canonical, "file.path", e.path);
        appendCanonicalField(canonical, "file.size", std::to_string(e.size));
        appendCanonicalField(canonical, "file.sha256", e.hash);
    }
    for (const auto& kv : fp.toolchain) {
        appendCanonicalField(canonical, "toolchain.key", kv.first);
        appendCanonicalField(canonical, "toolchain.value", kv.second);
    }
    for (const auto& kv : fp.env) {
        appendCanonicalField(canonical, "env.key", kv.first);
        appendCanonicalField(canonical, "env.value", kv.second);
    }
    fp.id = sha256Hex(canonical);
    return result;
}

JsonValue fingerprintToJson(const Fingerprint& fp) {
    JsonValue root = JsonValue::makeObject();
    root.object["version"] =
        JsonValue::makeNumber(static_cast<double>(fp.formatVersion));
    root.object["hash_algorithm"] = JsonValue::makeString(fp.hashAlgorithm);
    root.object["id"] = JsonValue::makeString(fp.id);
    root.object["os"] = JsonValue::makeString(fp.os);
    root.object["created"] = JsonValue::makeString(fp.created);

    JsonValue files = JsonValue::makeArray();
    for (const FileEntry& e : fp.files) {
        JsonValue o = JsonValue::makeObject();
        o.object["path"] = JsonValue::makeString(e.path);
        o.object["size"] = JsonValue::makeNumber(static_cast<double>(e.size));
        o.object["hash"] = JsonValue::makeString(e.hash);
        files.array.push_back(o);
    }
    root.object["files"] = files;

    JsonValue tc = JsonValue::makeObject();
    for (const auto& kv : fp.toolchain) {
        tc.object[kv.first] = JsonValue::makeString(kv.second);
    }
    root.object["toolchain"] = tc;

    JsonValue env = JsonValue::makeObject();
    for (const auto& kv : fp.env) {
        env.object[kv.first] = JsonValue::makeString(kv.second);
    }
    root.object["env"] = env;
    return root;
}

Fingerprint fingerprintFromJson(const JsonValue& v) {
    if (!v.isObject()) {
        throw std::runtime_error("fingerprint root must be an object");
    }

    double version = v.getNumber("version", 0.0);
    if (version == 0.0) {
        std::string legacyId = v.getString("id", "");
        if (legacyId.size() == 16) {
            throw std::runtime_error(
                "legacy fingerprint format v1 (FNV-1a-64) is unsupported; "
                "recompute it with the current tg fingerprint command");
        }
        throw std::runtime_error("fingerprint is missing supported format version 2");
    }
    if (version != 2.0) {
        throw std::runtime_error("unsupported fingerprint format version: " +
                                 std::to_string(static_cast<int>(version)));
    }

    Fingerprint fp;
    fp.formatVersion = 2;
    fp.hashAlgorithm = v.getString("hash_algorithm", "");
    if (fp.hashAlgorithm != "sha256") {
        throw std::runtime_error("unsupported fingerprint hash algorithm: " +
                                 fp.hashAlgorithm);
    }
    fp.id = v.getString("id", "");
    fp.os = v.getString("os", "");
    fp.created = v.getString("created", "");
    if (!isSha256Hex(fp.id)) {
        throw std::runtime_error("fingerprint 'id' must be a 64-hex SHA-256 digest");
    }

    if (v.has("files")) {
        const JsonValue& arr = v.at("files");
        if (!arr.isArray()) throw std::runtime_error("'files' must be an array");
        for (const JsonValue& item : arr.array) {
            if (!item.isObject()) {
                throw std::runtime_error("file entry must be an object");
            }
            FileEntry e;
            e.path = item.getString("path", "");
            e.size = static_cast<uint64_t>(item.getNumber("size", 0.0));
            e.hash = item.getString("hash", "");
            if (e.path.empty()) {
                throw std::runtime_error("file entry is missing 'path'");
            }
            if (!isSha256Hex(e.hash)) {
                throw std::runtime_error("file entry hash for '" + e.path +
                                         "' must be a 64-hex SHA-256 digest");
            }
            std::transform(e.hash.begin(), e.hash.end(), e.hash.begin(),
                           [](unsigned char c) {
                               return static_cast<char>(std::tolower(c));
                           });
            fp.files.push_back(e);
        }
    }

    auto getMap = [&](const char* key,
                      std::map<std::string, std::string>& dst) {
        if (!v.has(key)) return;
        const JsonValue& o = v.at(key);
        if (!o.isObject()) {
            throw std::runtime_error(std::string("'") + key +
                                     "' must be an object");
        }
        for (const auto& kv : o.object) {
            if (kv.second.isString()) dst[kv.first] = kv.second.str;
        }
    };
    getMap("toolchain", fp.toolchain);
    getMap("env", fp.env);
    return fp;
}

FpDiff diffFingerprints(const Fingerprint& oldFp, const Fingerprint& newFp) {
    FpDiff d;
    std::map<std::string, std::pair<uint64_t, std::string>> a, b;
    for (const FileEntry& e : oldFp.files) a[e.path] = {e.size, e.hash};
    for (const FileEntry& e : newFp.files) b[e.path] = {e.size, e.hash};

    for (const auto& kv : b) {
        auto it = a.find(kv.first);
        if (it == a.end()) {
            d.added.push_back(kv.first);
        } else if (it->second != kv.second) {
            d.changed.push_back(kv.first);
        }
    }
    for (const auto& kv : a) {
        if (b.find(kv.first) == b.end()) d.removed.push_back(kv.first);
    }
    std::sort(d.added.begin(), d.added.end());
    std::sort(d.removed.begin(), d.removed.end());
    std::sort(d.changed.begin(), d.changed.end());
    return d;
}

}  // namespace tg
