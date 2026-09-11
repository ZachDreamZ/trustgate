#pragma once

// Evidence policy (JSON). Missing file -> documented defaults + warning.
// {
//   "require_file_citation": true,
//   "require_test_citation": true,
//   "require_artifact_citation": false,
//   "quarantine_allow": true,
//   "deny_on_env_drift": false
// }

#include <string>

namespace tg {

struct Policy {
    bool requireFileCitation = true;
    bool requireTestCitation = true;
    bool requireArtifactCitation = false;
    bool quarantineAllow = true;
    bool denyOnEnvDrift = false;
};

// usedDefaults=true + warning set when the file is missing/invalid.
Policy loadPolicy(const std::string& path, bool& usedDefaults, std::string& warning);

std::string defaultPolicyJson(bool lenient);

}  // namespace tg
