#include "eval/eval.h"

#include <chrono>
#include <regex>
#include <stdexcept>

#include "core/fsutil.h"
#include "core/proc.h"

namespace tg {
namespace {

bool isAbsPath(const std::string& p) {
    if (p.empty()) return false;
    if (p[0] == '/' || p[0] == '\\') return true;
    return p.size() > 1 && p[1] == ':';  // Windows drive letter
}

std::string joinRepo(const std::string& root, const std::string& ref) {
    if (isAbsPath(ref)) return ref;
    std::string r = root;
    while (!r.empty() && (r.back() == '/' || r.back() == '\\')) r.pop_back();
    if (r.empty() || r == ".") return ref;
    return r + "/" + ref;
}

bool requireString(const JsonValue& o, const char* key, const std::string& what) {
    if (!o.has(key) || !o.at(key).isString() || o.at(key).str.empty()) {
        throw std::runtime_error(std::string("assert needs non-empty string '") + key + "' (" +
                                 what + ")");
    }
    return true;
}

// Walks objects by key and arrays by numeric index. Returns nullptr on miss.
const JsonValue* walkField(const JsonValue& root, const std::string& path) {
    const JsonValue* cur = &root;
    std::string::size_type start = 0;
    while (true) {
        std::string::size_type dot = path.find('.', start);
        std::string part = (dot == std::string::npos) ? path.substr(start)
                                                      : path.substr(start, dot - start);
        if (part.empty()) return nullptr;
        if (cur->isObject()) {
            auto it = cur->object.find(part);
            if (it == cur->object.end()) return nullptr;
            cur = &it->second;
        } else if (cur->isArray()) {
            try {
                std::size_t i = static_cast<std::size_t>(std::stoul(part));
                if (i >= cur->array.size()) return nullptr;
                cur = &cur->array[i];
            } catch (...) {
                return nullptr;
            }
        } else {
            return nullptr;
        }
        if (dot == std::string::npos) return cur;
        start = dot + 1;
    }
}

bool evalMatch(const Assert& a, const EvalResult& ctx, const std::string& repoRoot,
               std::string& detail) {
    if (a.pattern.empty()) {
        detail = "match: empty pattern";
        return false;
    }
    std::string corpus;
    if (!a.file.empty()) {
        try {
            corpus = readFile(joinRepo(repoRoot, a.file));
        } catch (const std::exception& ex) {
            detail = std::string("match: cannot read corpus file '") + a.file + "': " + ex.what();
            return false;
        }
        if (corpus.size() > (1 << 20)) corpus.resize(1 << 20);  // cap regex input
    } else if (ctx.hasRun) {
        corpus = ctx.output;
        if (corpus.size() > (1 << 20)) corpus.resize(1 << 20);
    } else {
        detail = "match: needs run.command or file";
        return false;
    }
    bool found = false;
    if (a.regex) {
        try {
            found = std::regex_search(corpus, std::regex(a.pattern));
        } catch (const std::regex_error& ex) {
            detail = std::string("match: bad regex '") + a.pattern + "': " + ex.what();
            return false;
        }
    } else {
        found = corpus.find(a.pattern) != std::string::npos;
    }
    if (found == a.present) return true;
    detail = std::string("match: pattern '") + a.pattern + (a.present ? "' absent" : "' present");
    return false;
}

}  // namespace

bool jsonEqual(const JsonValue& a, const JsonValue& b) {
    if (a.type != b.type) return false;
    switch (a.type) {
        case JsonValue::Type::Null: return true;
        case JsonValue::Type::Bool: return a.boolean == b.boolean;
        case JsonValue::Type::Number: return a.number == b.number;
        case JsonValue::Type::String: return a.str == b.str;
        case JsonValue::Type::Array:
            if (a.array.size() != b.array.size()) return false;
            for (std::size_t i = 0; i < a.array.size(); ++i) {
                if (!jsonEqual(a.array[i], b.array[i])) return false;
            }
            return true;
        case JsonValue::Type::Object:
            if (a.object.size() != b.object.size()) return false;
            for (const auto& kv : a.object) {
                auto it = b.object.find(kv.first);
                if (it == b.object.end() || !jsonEqual(kv.second, it->second)) return false;
            }
            return true;
    }
    return false;  // unreachable
}

EvalCase loadEvalFile(const std::string& path) {
    EvalCase c;
    c.file = path;
    JsonValue root = parseJson(readFile(path));  // may throw
    if (!root.isObject()) throw std::runtime_error("eval root must be an object: " + path);
    c.name = root.getString("name", "");
    if (c.name.empty()) {
        // Default to the filename stem.
        std::string base = path;
        std::string::size_type s = base.find_last_of("/\\");
        if (s != std::string::npos) base = base.substr(s + 1);
        std::string::size_type d = base.rfind('.');
        c.name = (d == std::string::npos) ? base : base.substr(0, d);
    }
    c.description = root.getString("description", "");
    if (root.has("run")) {
        if (!root.at("run").isString() || root.at("run").str.empty()) {
            throw std::runtime_error("'run' must be a non-empty command string: " + path);
        }
        c.command = root.at("run").str;
    }
    if (!root.has("asserts") || !root.at("asserts").isArray() ||
        root.at("asserts").array.empty()) {
        throw std::runtime_error("eval needs a non-empty 'asserts' array: " + path);
    }
    for (const JsonValue& item : root.at("asserts").array) {
        if (!item.isObject()) throw std::runtime_error("each assert must be an object: " + path);
        std::string type = item.getString("type", "");
        Assert a;
        if (type == "match") {
            a.type = AssertType::Match;
            requireString(item, "pattern", path);
            a.pattern = item.at("pattern").str;
            a.regex = item.getBool("regex", false);
            a.present = item.getBool("present", true);
            a.file = item.getString("file", "");
        } else if (type == "exit_code") {
            a.type = AssertType::ExitCode;
            a.expectedExit = static_cast<int>(item.getNumber("expected", 0.0));
        } else if (type == "file_exists") {
            a.type = AssertType::FileExists;
            requireString(item, "path", path);
            a.path = item.at("path").str;
        } else if (type == "json_field") {
            a.type = AssertType::JsonField;
            requireString(item, "file", path);
            requireString(item, "field", path);
            a.file = item.at("file").str;
            a.field = item.at("field").str;
            if (!item.has("equals")) {
                throw std::runtime_error("json_field needs 'equals': " + path);
            }
            a.equals = item.at("equals");
        } else if (type == "max_ms") {
            a.type = AssertType::MaxMs;
            a.maxMs = item.getNumber("value", 0.0);
            if (a.maxMs <= 0.0) throw std::runtime_error("max_ms needs positive 'value': " + path);
        } else {
            throw std::runtime_error("unknown assert type '" + type + "': " + path);
        }
        c.asserts.push_back(a);
    }
    return c;
}

EvalResult runEval(const EvalCase& c, const std::string& repoRoot) {
    EvalResult r;
    if (!c.command.empty()) {
        auto t0 = std::chrono::steady_clock::now();
        // NOTE: no timeout enforcement and no sandboxing in v0.1; the command
        // runs with user privileges. Keep eval commands fast and local.
        // runCapture merges stderr into stdout; that merged text is the corpus.
        std::string cmd = c.command;
        if (!repoRoot.empty() && repoRoot != ".") {
            // Run from the repo root so relative paths behave. pushd-style
            // prefix keeps a single shell invocation on both platforms.
            cmd = "cd \"" + repoRoot + "\" && " + cmd;
        }
        ProcResult proc = runCapture(cmd);
        auto t1 = std::chrono::steady_clock::now();
        r.hasRun = true;
        r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        r.output = proc.output;
        r.exitCode = proc.exitCode;
    }
    for (std::size_t i = 0; i < c.asserts.size(); ++i) {
        const Assert& a = c.asserts[i];
        std::string detail;
        bool ok = false;
        try {
            switch (a.type) {
                case AssertType::Match:
                    ok = evalMatch(a, r, repoRoot, detail);
                    break;
                case AssertType::ExitCode:
                    if (!r.hasRun) {
                        detail = "exit_code: needs run.command";
                    } else if (r.exitCode == a.expectedExit) {
                        ok = true;
                    } else {
                        detail = "exit_code: got " + std::to_string(r.exitCode) + ", expected " +
                                 std::to_string(a.expectedExit);
                    }
                    break;
                case AssertType::FileExists:
                    if (fileExists(joinRepo(repoRoot, a.path))) {
                        ok = true;
                    } else {
                        detail = "file_exists: not found '" + a.path + "'";
                    }
                    break;
                case AssertType::JsonField: {
                    const JsonValue* v = nullptr;
                    JsonValue doc = JsonValue::makeNull();
                    try {
                        doc = parseJson(readFile(joinRepo(repoRoot, a.file)));
                        v = walkField(doc, a.field);
                    } catch (const std::exception& ex) {
                        detail = std::string("json_field: cannot load '") + a.file +
                                 "': " + ex.what();
                        break;
                    }
                    if (v == nullptr) {
                        detail = "json_field: no such field '" + a.field + "' in '" + a.file + "'";
                    } else if (jsonEqual(*v, a.equals)) {
                        ok = true;
                    } else {
                        detail = "json_field: '" + a.field + "' is " + toJson(*v) + ", expected " +
                                 toJson(a.equals);
                    }
                    break;
                }
                case AssertType::MaxMs:
                    if (!r.hasRun) {
                        detail = "max_ms: needs run.command";
                    } else if (static_cast<double>(r.ms) <= a.maxMs) {
                        ok = true;
                    } else {
                        detail = "max_ms: took " + std::to_string(r.ms) + "ms, budget " +
                                 std::to_string(static_cast<long long>(a.maxMs)) + "ms";
                    }
                    break;
            }
        } catch (const std::exception& ex) {
            detail = std::string("internal error: ") + ex.what();
        } catch (...) {
            detail = "internal error";
        }
        if (!ok) {
            AssertFailure f;
            f.index = static_cast<int>(i);
            f.message = detail.empty() ? "assertion failed" : detail;
            r.failures.push_back(f);
        }
    }
    r.passed = r.failures.empty();
    return r;
}

}  // namespace tg
