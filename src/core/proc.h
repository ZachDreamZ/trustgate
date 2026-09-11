#pragma once

// Best-effort child-process capture for toolchain probes.
// Merges stderr into stdout. Never throws; failures are reported
// via ProcResult.ok == false. No timeout enforcement in v0.1.

#include <string>

namespace tg {

struct ProcResult {
    bool ok = false;  // true when exitCode == 0
    int exitCode = -1;  // decoded process exit code (POSIX wait-status
                        // decoded; 128+signal when killed by a signal)
    std::string output;  // captured output (capped, see below)
    std::size_t bytesWritten = 0;  // bytes streamed (runCaptureToFile)
    bool truncated = false;  // true when a capture cap was hit
};

// In-memory capture cap. Large outputs belong in runCaptureToFile.
const std::size_t kCaptureMaxBytes = 4 << 20;   // 4MB
// Streaming capture cap for command logs.
const std::size_t kLogMaxBytes = 64ULL << 20;  // 64MB

ProcResult runCapture(const std::string& command);

// Streams child output straight to a log file (no full buffering), so large
// outputs stay faithful. Caps at kLogMaxBytes and keeps draining afterwards
// so the child always finishes and the exit code stays truthful; sets
// truncated when the cap was hit. output is left empty; check bytesWritten.
ProcResult runCaptureToFile(const std::string& command, const std::string& logPath);

// First non-empty line of output, or "" when the probe failed.
std::string probeFirstLine(const std::string& command);

}  // namespace tg
