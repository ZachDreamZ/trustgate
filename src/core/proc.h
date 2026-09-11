#pragma once

// Best-effort child-process capture for toolchain probes.
// Merges stderr into stdout. Never throws; failures are reported
// via ProcResult.ok == false. No timeout enforcement in v0.1.

#include <string>

namespace tg {

struct ProcResult {
    bool ok = false;
    int exitCode = -1;
    std::string output;  // first line trimmed by callers as needed
};

ProcResult runCapture(const std::string& command);

// First non-empty line of output, or "" when the probe failed.
std::string probeFirstLine(const std::string& command);

}  // namespace tg
