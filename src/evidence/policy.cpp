#include "evidence/policy.h"

#include "core/fsutil.h"
#include "core/json.h"

namespace tg {

Policy loadPolicy(const std::string& path, bool& usedDefaults, std::string& warning) {
    Policy p;
    usedDefaults = false;
    warning.clear();
    if (!fileExists(path)) {
        usedDefaults = true;
        warning = "policy file not found: " + path + " (using defaults)";
        return p;
    }
    try {
        JsonValue root = parseJson(readFile(path));
        if (!root.isObject()) throw JsonError("policy root must be an object");
        p.requireFileCitation = root.getBool("require_file_citation", true);
        p.requireTestCitation = root.getBool("require_test_citation", true);
        p.requireArtifactCitation = root.getBool("require_artifact_citation", false);
        p.quarantineAllow = root.getBool("quarantine_allow", true);
        p.denyOnEnvDrift = root.getBool("deny_on_env_drift", false);
    } catch (const std::exception& ex) {
        usedDefaults = true;
        warning = std::string("policy file invalid, using defaults: ") + ex.what();
        return Policy();
    }
    return p;
}

std::string defaultPolicyJson(bool lenient) {
    JsonValue root = JsonValue::makeObject();
    root.object["require_file_citation"] = JsonValue::makeBool(true);
    root.object["require_test_citation"] = JsonValue::makeBool(true);
    root.object["require_artifact_citation"] = JsonValue::makeBool(false);
    root.object["quarantine_allow"] = JsonValue::makeBool(true);
    root.object["deny_on_env_drift"] = JsonValue::makeBool(false);
    if (lenient) {
        // Lenient starter policy: artifact citations still optional, and the
        // CLI --lenient flag (not the file) controls warn-only mode.
        root.object["comment"] =
            JsonValue::makeString("starter policy from `tg init --lenient`; tighten over time");
    }
    return toJson(root, true) + "\n";
}

}  // namespace tg
