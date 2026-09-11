#pragma once

// Minimal SARIF 2.1.0 writer for gate findings.

#include <string>

#include "evidence/verifier.h"

namespace tg {

std::string buildSarif(const VerifyReport& report, const std::string& toolVersion);

}  // namespace tg
