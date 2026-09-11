#include "evidence/sarif.h"

#include <map>

#include "core/json.h"

namespace tg {

std::string buildSarif(const VerifyReport& report, const std::string& toolVersion) {
    JsonValue root = JsonValue::makeObject();
    root.object["version"] = JsonValue::makeString("2.1.0");
    root.object["$schema"] =
        JsonValue::makeString("https://json.schemastore.org/sarif-2.1.0.json");

    // Collect rules in first-seen order.
    std::map<std::string, int> ruleIndex;
    JsonValue rules = JsonValue::makeArray();
    for (const Finding& f : report.findings) {
        if (ruleIndex.find(f.rule) != ruleIndex.end()) continue;
        ruleIndex[f.rule] = static_cast<int>(rules.array.size());
        JsonValue rule = JsonValue::makeObject();
        rule.object["id"] = JsonValue::makeString("trustgate/" + f.rule);
        rule.object["name"] = JsonValue::makeString(f.rule);
        JsonValue desc = JsonValue::makeObject();
        desc.object["text"] = JsonValue::makeString("TrustGate evidence-gate finding: " + f.rule);
        rule.object["shortDescription"] = desc;
        rules.array.push_back(rule);
    }

    JsonValue results = JsonValue::makeArray();
    for (const Finding& f : report.findings) {
        JsonValue res = JsonValue::makeObject();
        res.object["ruleId"] = JsonValue::makeString("trustgate/" + f.rule);
        res.object["level"] = JsonValue::makeString(f.severity == "error" ? "error" : "warning");
        JsonValue msg = JsonValue::makeObject();
        msg.object["text"] = JsonValue::makeString(f.message);
        res.object["message"] = msg;
        JsonValue loc = JsonValue::makeObject();
        JsonValue phys = JsonValue::makeObject();
        JsonValue art = JsonValue::makeObject();
        art.object["uri"] = JsonValue::makeString("claims.json");
        phys.object["artifactLocation"] = art;
        loc.object["physicalLocation"] = phys;
        JsonValue locs = JsonValue::makeArray();
        locs.array.push_back(loc);
        res.object["locations"] = locs;
        JsonValue props = JsonValue::makeObject();
        props.object["claimId"] = JsonValue::makeString(f.claimId);
        res.object["properties"] = props;
        results.array.push_back(res);
    }

    JsonValue driver = JsonValue::makeObject();
    driver.object["name"] = JsonValue::makeString("TrustGate");
    driver.object["version"] = JsonValue::makeString(toolVersion);
    driver.object["rules"] = rules;
    JsonValue tool = JsonValue::makeObject();
    tool.object["driver"] = driver;
    JsonValue run = JsonValue::makeObject();
    run.object["tool"] = tool;
    run.object["results"] = results;
    JsonValue runs = JsonValue::makeArray();
    runs.array.push_back(run);
    root.object["runs"] = runs;

    return toJson(root, true) + "\n";
}

}  // namespace tg
