#include "repro/fingerprint.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <thread>

#include "core/fsutil.h"
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

FingerprintResult computeFingerprint(const FingerprintOptions& opts) {
    FingerprintResult result;
    Fingerprint& fp = result.fp;
    fp.os = osName();
    fp.created = utcNowIso();

    std::vector<std::pair<std::string, std::string>> targets;  // (rel, full)
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
            targets.emplace_back(rel.generic_string(), p.generic_string());
        }
    }
    std::sort(targets.begin(), targets.end(),
              [](const std::pair<std::string, std::string>& a,
                 const std::pair<std::string, std::string>& b) { return a.first < b.first; });

    // Hash contents with a portable std::thread pool (no TBB needed for
    // <execution> policies, so Linux CI stays dependency-free).
    // Order-independent: each file hashes alone; results land by index,
    // and the ID mixes them in sorted order afterwards.
    std::vector<FileEntry> hashed(targets.size());
    std::vector<char> ready(targets.size(), 0);
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
            try {
                std::string data = readFile(targets[i].second);
                hashed[i].path = targets[i].first;
                hashed[i].size = static_cast<uint64_t>(data.size());
                hashed[i].hash = fnv1a64(data);
                ready[i] = 1;
            } catch (...) {
                skippedCount.fetch_add(1, std::memory_order_relaxed);
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
