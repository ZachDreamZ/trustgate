#pragma once

// Tolerant JUnit XML scanner. Handles <testsuite>/<testcase> with
// <failure|error|skipped> children, self-closing or paired tags.
// Attribute quotes may be " or '. Unknown elements are ignored.

#include <string>
#include <vector>

namespace tg {

struct TestCaseResult {
    std::string id;   // "classname.name" or bare "name"
    char status = 'P';  // 'P' passed, 'F' failed/error, 'S' skipped
    double timeMs = 0.0;
};

struct JUnitReport {
    std::vector<TestCaseResult> cases;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
};

JUnitReport parseJUnit(const std::string& xml);

std::string junitIdentity(const std::string& classname, const std::string& name);

}  // namespace tg
