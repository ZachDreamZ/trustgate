#pragma once

// Tolerant JUnit XML scanner. Handles <testsuite>/<testcase> with
// <failure|error|skipped> children, self-closing or paired tags.
// Attribute quotes may be " or '. Unknown elements are ignored.

#include <map>
#include <string>
#include <vector>

namespace tg {

struct TestCaseResult {
    std::string id;   // "classname.name" or bare "name"
    std::string name;
    std::string classname;
    std::vector<std::string> suites;  // outermost to innermost suite names
    char status = 'P';  // 'P' passed, 'F' failed/error, 'S' skipped
    double timeMs = 0.0;
    // message="..." of the first failure/error child plus a collapsed
    // excerpt of its body (capped); empty unless status == 'F'.
    std::string failureText;
};

struct JUnitReport {
    std::vector<TestCaseResult> cases;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
};

JUnitReport parseJUnit(const std::string& xml);

std::string junitIdentity(const std::string& classname, const std::string& name);

struct ResolvedJUnitTest {
    char status = 'P';  // 'P' | 'F' | 'S' | 'A' (ambiguous citation)
    // Canonical flake/quarantine id, empty unless that id is unambiguous too.
    std::string quarantineId;
};

// Gate references: bare name, classname.name, and suite path + "." + id.
// Distinct suite/class/name identities sharing a reference yield 'A' (ambiguous).
// Repeated observations of one identity merge with worst status F > S > P.
std::map<std::string, ResolvedJUnitTest> junitTestStatus(const std::vector<TestCaseResult>& cases);

}  // namespace tg
