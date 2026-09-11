#include "core/proc.h"

#include <array>
#include <cstdio>

#if defined(_WIN32)
#define TG_POPEN _popen
#define TG_PCLOSE _pclose
#else
#define TG_POPEN popen
#define TG_PCLOSE pclose
#endif

namespace tg {

ProcResult runCapture(const std::string& command) {
    ProcResult r;
    std::string full = command + " 2>&1";
    FILE* pipe = TG_POPEN(full.c_str(), "r");
    if (pipe == nullptr) return r;
    std::array<char, 4096> buf{};
    std::string out;
    std::size_t n = 0;
    while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
        out += buf.data();
        if (out.size() > 65536) break;  // guard against banner spam
        ++n;
        (void)n;
    }
    int rc = TG_PCLOSE(pipe);
    r.ok = (rc == 0);
    r.exitCode = rc;
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

}  // namespace tg
