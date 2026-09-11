#pragma once

// EvalOps Lite: deterministic scenario files (evals/*.json), no LLM judge.
// Schema: {"name","description","run":"shell command or omitted",
//   "asserts":[{"type":"match","pattern","regex":false,"present":true,
//               "file":"corpus path or omitted (else run output)"},
//              {"type":"exit_code","expected":0},
//              {"type":"file_exists","path":"..."},
//              {"type":"json_field","file":"...","field":"a.b.0","equals":...},
//              {"type":"max_ms","value":5000}]}
// Run commands execute with user privileges and no timeout enforcement;
// keep them fast, local, and side-effect free. Live examples: evals/.

#include <string>
#include <vector>

#include "core/json.h"

namespace tg {

enum class AssertType { Match, ExitCode, FileExists, JsonField, MaxMs };

struct Assert {
    AssertType type = AssertType::Match;
    // Match:
    std::string pattern;
    bool regex = false;
    bool present = true;
    std::string file;  // corpus file (relative to repoRoot); empty = run output
    // ExitCode:
    int expectedExit = 0;
    // FileExists:
    std::string path;
    // JsonField:
    std::string field;  // dot path, e.g. "stats.errors" (numeric = array index)
    JsonValue equals = JsonValue::makeNull();
    // MaxMs:
    double maxMs = 0.0;
};

struct EvalCase {
    std::string name;
    std::string description;
    std::string file;     // definition path (for reports)
    std::string command;  // empty = static eval (no run)
    std::vector<Assert> asserts;
};

// Throws std::runtime_error / JsonError on invalid input.
EvalCase loadEvalFile(const std::string& path);

struct AssertFailure {
    int index = -1;
    std::string message;
};

struct EvalResult {
    bool passed = false;
    bool hasRun = false;
    long long ms = 0;
    std::string output;  // captured run output (stdout+stderr merged)
    int exitCode = -1;   // -1 when no run
    std::vector<AssertFailure> failures;
};

EvalResult runEval(const EvalCase& c, const std::string& repoRoot);

bool jsonEqual(const JsonValue& a, const JsonValue& b);

}  // namespace tg
