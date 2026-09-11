#include "core/proc.h"

#include <array>
#include <cstdio>

#include "core/fsutil.h"
#include <fstream>

#if defined(_WIN32)
#define TG_POPEN _popen
#define TG_PCLOSE _pclose
#define TG_READMODE "rb"  // binary: no CRLF->LF translation, no Ctrl+Z EOF
#else
#define TG_POPEN popen
#define TG_PCLOSE pclose
#define TG_READMODE "r"  // 'b' ignored on POSIX; kept distinct for clarity
#include <sys/wait.h>
#endif

namespace tg {

ProcResult runCapture(const std::string& command) {
    ProcResult r;
    std::string full = command + " 2>&1";
    FILE* pipe = TG_POPEN(full.c_str(), TG_READMODE);
    if (pipe == nullptr) return r;
    std::array<char, 4096> buf{};
    std::string out;
    std::size_t n = 0;
    while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
        out += buf.data();
        if (out.size() > kCaptureMaxBytes) {
            // Cap in-memory captures: callers with big outputs must stream
            // via runCaptureToFile. Keep draining so the child finishes and
            // the exit code stays truthful, then truncate.
            r.truncated = true;
            while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
            }
            break;
        }
        ++n;
        (void)n;
    }
    int rc = TG_PCLOSE(pipe);
#if defined(_WIN32)
    // _pclose returns the child exit code directly.
    r.exitCode = rc;
#else
    // pclose returns a wait(2) status: decode it to the real exit code so
    // callers (eval exit_code asserts, wrap passthrough) see process truth.
    if (WIFEXITED(rc)) {
        r.exitCode = WEXITSTATUS(rc);
    } else if (WIFSIGNALED(rc)) {
        r.exitCode = 128 + WTERMSIG(rc);  // shell convention for signals
    } else {
        r.exitCode = rc;
    }
#endif
    r.ok = (r.exitCode == 0);
    r.output = out;
    return r;
}

std::string probeFirstLine(const std::string& command) {
    ProcResult r = runCapture(command);
    if (!r.ok) return "";
    std::string::size_type nl = r.output.find_first_of("\r\n");
    std::string line = (nl == std::string::npos) ? r.output : r.output.substr(0, nl);
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
        line.pop_back();
    }
    return line;
}

ProcResult runCaptureToFile(const std::string& command, const std::string& logPath) {
    ProcResult r;
    std::string full = command + " 2>&1";
    FILE* pipe = TG_POPEN(full.c_str(), TG_READMODE);
    if (pipe == nullptr) return r;
    std::ofstream log(pathFromUtf8(logPath), std::ios::binary | std::ios::trunc);
    if (!log) {
        // Unwritable log: drain so the child still finishes, then report.
        std::array<char, 65536> drain{};
        while (std::fgets(drain.data(), static_cast<int>(drain.size()), pipe) != nullptr) {
        }
        TG_PCLOSE(pipe);
        return r;
    }
    std::array<char, 65536> buf{};
    std::size_t written = 0;
    std::size_t n = 0;
    bool writeOk = true;
    while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
        std::string chunk = buf.data();
        // Always drain the pipe to EOF (even capped or on disk error) so the
        // child finishes normally and the exit code stays truthful.
        if (writeOk && written < kLogMaxBytes) {
            std::size_t room = kLogMaxBytes - written;
            if (chunk.size() > room) {
                log.write(chunk.data(), static_cast<std::streamsize>(room));
                written += room;
                r.truncated = true;
            } else {
                log.write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
                written += chunk.size();
            }
            if (!log) writeOk = false;
        }
        ++n;
        (void)n;
    }
    log.close();
    r.bytesWritten = written;
    int rc = TG_PCLOSE(pipe);
#if defined(_WIN32)
    r.exitCode = rc;
#else
    if (WIFEXITED(rc)) {
        r.exitCode = WEXITSTATUS(rc);
    } else if (WIFSIGNALED(rc)) {
        r.exitCode = 128 + WTERMSIG(rc);
    } else {
        r.exitCode = rc;
    }
#endif
    r.ok = (r.exitCode == 0);
    return r;
}

}  // namespace tg
