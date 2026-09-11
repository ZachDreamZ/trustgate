#include "repro/fingerprint.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <tuple>

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

unsigned long long parseHex64(const std::string& s) {
    if (s.size() != 16) throw std::runtime_error("bad hash hex: " + s);
    unsigned long long v = 0;
    for (char c : s) {
        v <<= 4;
        if (c >= '0' && c <= '9') {
            v |= static_cast<unsigned long long>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v |= static_cast<unsigned long long>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v |= static_cast<unsigned long long>(c - 'A' + 10);
        } else {
            throw std::runtime_error("bad hash hex: " + s);
        }
    }
    return v;
}

}  // namespace

namespace {

// Hash-cache helpers. Entries are keyed by relative path; a hit requires an
// exact (size, mtime) match, mtime in 100ns ticks stored as a decimal string
// (JSON doubles cannot hold 64-bit timestamps exactly).
// Corrupt/version-mismatched caches start fresh; cache I/O never fails a run.

const char* kCacheAlgo = "fnv1a64-1";

using CacheMap = std::map<std::string, std::tuple<uint64_t, long long, uint64_t>>;

CacheMap loadHashCache(const std::string& path) {
    CacheMap out;
    if (!fileExists(path)) return out;
    try {
        JsonValue root = parseJson(readFile(path));
        if (!root.isObject()) return out;
        if (root.getNumber("version", 0.0) != 1.0) return out;
        if (root.getString("algo", "") != kCacheAlgo) return out;
        if (!root.has("entries")) return out;
        const JsonValue& entries = root.at("entries");
        if (!entries.isObject()) return out;
        for (const auto& kv : entries.object) {
            if (!kv.second.isObject()) continue;
            double sizeNum = kv.second.getNumber("size", -1.0);
            std::string mtimeStr = kv.second.getString("mtime_100ns", "");
            std::string hex = kv.second.getString("hash", "");
            if (sizeNum < 0.0 || sizeNum > 9.0e15 || mtimeStr.empty() || hex.size() != 16) {
                continue;
            }
            char* end = nullptr;
            long long mtime = std::strtoll(mtimeStr.c_str(), &end, 10);
            if (end == nullptr || *end != '\0' || mtime < 0) continue;
            uint64_t h = 0;
            bool bad = false;
            for (char c : hex) {
                h <<= 4;
                if (c >= '0' && c <= '9') {
                    h |= static_cast<uint64_t>(c - '0');
                } else if (c >= 'a' && c <= 'f') {
                    h |= static_cast<uint64_t>(c - 'a' + 10);
                } else if (c >= 'A' && c <= 'F') {
                    h |= static_cast<uint64_t>(c - 'A' + 10);
                } else {
                    bad = true;
                    break;
                }
            }
            if (bad) continue;
            out[kv.first] = std::make_tuple(static_cast<uint64_t>(sizeNum), mtime, h);
        }
    } catch (...) {
        // Corrupt cache starts fresh.
    }
    return out;
}

bool saveHashCache(const std::string& path, const CacheMap& cache) {
    JsonValue root = JsonValue::makeObject();
    root.object["version"] = JsonValue::makeNumber(1.0);
    root.object["algo"] = JsonValue::makeString(kCacheAlgo);
    JsonValue entries = JsonValue::makeObject();
    for (const auto& kv : cache) {
        JsonValue e = JsonValue::makeObject();
        e.object["size"] = JsonValue::makeNumber(static_cast<double>(std::get<0>(kv.second)));
        e.object["mtime_100ns"] = JsonValue::makeString(std::to_string(std::get<1>(kv.second)));
        e.object["hash"] = JsonValue::makeString(toHex16(std::get<2>(kv.second)));
        entries.object[kv.first] = e;
    }
    root.object["entries"] = entries;
    ensureParentDir(path);
    std::string tmp = path + ".tmp";
    if (!writeFile(tmp, toJson(root))) return false;
    std::error_code ec;
    fs::rename(tmp, path, ec);
    return !ec;
}

}  // namespace

FingerprintResult computeFingerprint(const FingerprintOptions& opts) {
    FingerprintResult result;
    Fingerprint& fp = result.fp;
    fp.os = osName();
    fp.created = utcNowIso();

    struct Target {
        std::string rel;   // relative, '/' separators
        std::string full;  // absolute-ish path for reading
        uint64_t size = 0;
        long long mtimeNs = -1;  // 100ns ticks; -1 = stat failed, never cached
    };
    std::vector<Target> targets;
    std::error_code ec;
    fs::path rootPath(opts.root);
    if (!fs::exists(rootPath, ec)) {
        result.warnings.push_back("root does not exist: " + opts.root);
    } else {
        fs::recursive_directory_iterator it(rootPath,
                                            fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;
        for (; !ec && it != end; it.increment(ec)) {
            if (ec) {
                ++result.skipped;
                ec.clear();
                continue;
            }
            const fs::path& p = it->path();
            std::string name = p.filename().generic_string();
            if (it->is_directory(ec)) {
                if (!ec && isIgnoredDir(name)) it.disable_recursion_pending();
                continue;
            }
            if (ec) {
                ++result.skipped;
                ec.clear();
                continue;
            }
            if (!it->is_regular_file(ec) || ec) {
                ++result.skipped;  // symlinks, sockets, etc. are out of scope v0.1
                ec.clear();
                continue;
            }
            if (isExcludedFile(name, opts.excludeFilenames)) continue;
            std::error_code relEc;
            fs::path rel = fs::relative(p, rootPath, relEc);
            if (relEc) {
                ++result.skipped;
                continue;
            }
            Target t;
            t.rel = rel.generic_string();
            t.full = p.generic_string();
            std::error_code szEc, tmEc;
            t.size = it->file_size(szEc);
            if (szEc) t.size = 0;
            auto ft = it->last_write_time(tmEc);
            if (!tmEc) {
                // 100ns ticks: lossless on Windows (FILETIME-native) and fits
                // int64 (raw nanoseconds since 1601 would overflow int64).
                using ticks100ns =
                    std::chrono::duration<long long, std::ratio<1, 10000000>>;
                t.mtimeNs = std::chrono::duration_cast<ticks100ns>(ft.time_since_epoch())
                                .count();
            }
            targets.push_back(t);
        }
    }
    std::sort(targets.begin(), targets.end(),
              [](const Target& a, const Target& b) { return a.rel < b.rel; });

    // Hash cache: exact (size, mtime-ns) hits skip I/O entirely.
    // Best effort: corrupt/missing cache starts fresh, never fails the run.
    CacheMap cache;
    bool cacheUsable = opts.useCache && !opts.cachePath.empty();
    if (cacheUsable) {
        cache = loadHashCache(opts.cachePath);
    }

    // Hash contents with a portable std::thread pool (no TBB needed for
    // <execution> policies, so Linux CI stays dependency-free).
    // Order-independent: each file hashes alone; results land by index,
    // and the ID mixes them in sorted order afterwards.
    // Files are read via memory mapping (zero-copy page-cache access);
    // cache hits skip I/O entirely.
    std::vector<FileEntry> hashed(targets.size());
    std::vector<char> ready(targets.size(), 0);
    std::vector<char> fromCache(targets.size(), 0);
    std::atomic<std::size_t> next{0};
    std::atomic<int> skippedCount{result.skipped};
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
            if (t.mtimeNs >= 0) {
                auto cit = cache.find(t.rel);
                if (cit != cache.end() && std::get<0>(cit->second) == t.size &&
                    std::get<1>(cit->second) == t.mtimeNs) {
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
                hashed[i].hash = fnv1a64(mf.data(), mf.size());
                ready[i] = 1;
            } else {
                try {
                    std::string data = readFile(t.full);
                    hashed[i].path = t.rel;
                    hashed[i].size = static_cast<uint64_t>(data.size());
                    hashed[i].hash = fnv1a64(data);
                    ready[i] = 1;
                } catch (...) {
                    skippedCount.fetch_add(1, std::memory_order_relaxed);
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
        // Refresh: current results overwrite stale entries; deleted files drop.
        CacheMap fresh;
        for (std::size_t i = 0; i < hashed.size(); ++i) {
            if (ready[i] && targets[i].mtimeNs >= 0) {
                fresh[targets[i].rel] =
                    std::make_tuple(hashed[i].size, targets[i].mtimeNs, hashed[i].hash);
            }
        }
        if (!saveHashCache(opts.cachePath, fresh)) {
            result.warnings.push_back("cannot write hash cache: " + opts.cachePath);
        } else {
            int hits = 0;
            for (char c : fromCache) hits += c;
            if (hits > 0) {
                std::ostringstream note;
                note << "hash cache: " << hits << "/" << targets.size() << " reused";
                result.warnings.push_back(note.str());
            }
        }
    }

    // Toolchain probes: best effort, never fail the fingerprint.
    if (opts.probeToolchain) {
        std::string git = probeFirstLine("git --version");
        if (!git.empty()) fp.toolchain["git"] = git;
        std::string cmake = probeFirstLine("cmake --version");
        if (!cmake.empty()) {
            std::string::size_type nl = cmake.find_first_of("\r\n");
            fp.toolchain["cmake"] = (nl == std::string::npos) ? cmake : cmake.substr(0, nl);
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

    // Canonical ID over sorted content + toolchain + env.
    uint64_t h = 14695981039346656037ULL;
    auto mixStr = [&](const std::string& s) {
        h = hashCombine(h, fnv1a64(s));
    };
    for (const FileEntry& e : fp.files) {
        mixStr(e.path);
        h = hashCombine(h, e.size);
        h = hashCombine(h, e.hash);
    }
    for (const auto& kv : fp.toolchain) {
        mixStr(kv.first);
        mixStr(kv.second);
    }
    for (const auto& kv : fp.env) {
        mixStr(kv.first);
        mixStr(kv.second);
    }
    fp.id = toHex16(h);
    return result;
}

JsonValue fingerprintToJson(const Fingerprint& fp) {
    JsonValue root = JsonValue::makeObject();
    root.object["id"] = JsonValue::makeString(fp.id);
    root.object["os"] = JsonValue::makeString(fp.os);
    root.object["created"] = JsonValue::makeString(fp.created);
    JsonValue files = JsonValue::makeArray();
    for (const FileEntry& e : fp.files) {
        JsonValue o = JsonValue::makeObject();
        o.object["path"] = JsonValue::makeString(e.path);
        o.object["size"] = JsonValue::makeNumber(static_cast<double>(e.size));
        o.object["hash"] = JsonValue::makeString(toHex16(e.hash));
        files.array.push_back(o);
    }
    root.object["files"] = files;
    JsonValue tc = JsonValue::makeObject();
    for (const auto& kv : fp.toolchain) tc.object[kv.first] = JsonValue::makeString(kv.second);
    root.object["toolchain"] = tc;
    JsonValue env = JsonValue::makeObject();
    for (const auto& kv : fp.env) env.object[kv.first] = JsonValue::makeString(kv.second);
    root.object["env"] = env;
    return root;
}

Fingerprint fingerprintFromJson(const JsonValue& v) {
    if (!v.isObject()) throw std::runtime_error("fingerprint root must be an object");
    Fingerprint fp;
    fp.id = v.getString("id", "");
    fp.os = v.getString("os", "");
    fp.created = v.getString("created", "");
    if (fp.id.empty()) throw std::runtime_error("fingerprint is missing 'id'");
    if (v.has("files")) {
        const JsonValue& arr = v.at("files");
        if (!arr.isArray()) throw std::runtime_error("'files' must be an array");
        for (const JsonValue& item : arr.array) {
            FileEntry e;
            e.path = item.getString("path", "");
            e.size = static_cast<uint64_t>(item.getNumber("size", 0.0));
            e.hash = parseHex64(item.getString("hash", "0000000000000000"));
            if (e.path.empty()) throw std::runtime_error("file entry is missing 'path'");
            fp.files.push_back(e);
        }
    }
    auto getMap = [&](const char* key, std::map<std::string, std::string>& dst) {
        if (!v.has(key)) return;
        const JsonValue& o = v.at(key);
        if (!o.isObject()) throw std::runtime_error(std::string("'") + key + "' must be an object");
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
    std::map<std::string, std::pair<uint64_t, uint64_t>> a, b;
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
