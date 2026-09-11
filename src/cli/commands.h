#pragma once

#include <string>
#include <vector>

namespace tg {

extern const char* kTgVersion;  // defined in main.cpp; keep in sync with CMake

void printTopHelp();

int cmdInit(const std::vector<std::string>& args);
int cmdGate(const std::vector<std::string>& args);
int cmdFingerprint(const std::vector<std::string>& args);
int cmdFlake(const std::vector<std::string>& args);
int cmdEval(const std::vector<std::string>& args);
int cmdSign(const std::vector<std::string>& args);
int cmdVerify(const std::vector<std::string>& args);
int cmdWrap(const std::vector<std::string>& args);

}  // namespace tg
