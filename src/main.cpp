// TrustGate: local trust gate for AI-written code. See README.md.
// Exit codes: 0 pass, 2 DENY/drift, 1 usage or IO error, 3 not implemented.

#include <iostream>
#include <string>
#include <vector>

#include "cli/commands.h"

namespace tg {
const char* kTgVersion = "0.2.0";
}  // namespace tg

int main(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);

    if (args.empty()) {
        tg::printTopHelp();
        return 1;
    }
    const std::string& cmd = args[0];
    std::vector<std::string> rest(args.begin() + 1, args.end());

    if (cmd == "--version" || cmd == "-V" || cmd == "version") {
        std::cout << "tg " << tg::kTgVersion << "\n";
        return 0;
    }
    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        tg::printTopHelp();
        return 0;
    }
    if (cmd == "init") return tg::cmdInit(rest);
    if (cmd == "gate") return tg::cmdGate(rest);
    if (cmd == "fingerprint" || cmd == "fp") return tg::cmdFingerprint(rest);
    if (cmd == "flake") return tg::cmdFlake(rest);
    if (cmd == "eval") return tg::cmdEval(rest);
    if (cmd == "sign") return tg::cmdSign(rest);
    if (cmd == "verify") return tg::cmdVerify(rest);
    if (cmd == "wrap") return tg::cmdWrap(rest);

    std::cerr << "unknown command: " << cmd << "\n\n";
    tg::printTopHelp();
    return 1;
}
