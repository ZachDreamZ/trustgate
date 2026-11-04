#include "flake/junit.h"

#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <tuple>

namespace tg {

std::string junitIdentity(const std::string& classname, const std::string& name) {
    if (classname.empty()) return name;
    return classname + "." + name;
}

namespace {

// Returns attribute value or "". Handles both quote styles. Matches only
// standalone attribute names (preceded by whitespace), so "name" never
// matches inside "classname".
std::string getAttr(const std::string& tag, const std::string& name) {
    const std::string key = name + "=";
    std::string::size_type from = 0;
    while (true) {
        std::string::size_type pos = tag.find(key, from);
        if (pos == std::string::npos) return "";
        if (pos == 0) return "";  // malformed tag; bail out
        char prev = tag[pos - 1];
        if (prev == ' ' || prev == '\t' || prev == '\n' || prev == '\r') {
            std::string::size_type vpos = pos + key.size();
            if (vpos >= tag.size()) return "";
            char q = tag[vpos];
            if (q != '"' && q != '\'') {
                from = pos + 1;
                continue;
            }
            std::string::size_type end = tag.find(q, vpos + 1);
            if (end == std::string::npos) return "";
            return tag.substr(vpos + 1, end - vpos - 1);
        }
        from = pos + 1;
    }
}

std::string::size_type tagEnd(const std::string& xml, std::string::size_type at) {
    char quote = 0;
    for (auto i = at + 1; i < xml.size(); ++i) {
        char c = xml[i];
        if (quote) {
            if (c == quote) quote = 0;
        } else if (c == '\'' || c == '"') {
            quote = c;
        } else if (c == '>') {
            return i;
        }
    }
    return std::string::npos;
}

struct XmlTag {
    std::string::size_type at = 0;
    std::string::size_type end = 0;
    std::string name;
    bool closing = false;
    bool selfClosing = false;
};

// Suite nesting, testcase boundaries and statuses share this lexical boundary.
// Text regions never produce tags, and quoted '>' never ends a tag.
bool nextTag(const std::string& xml, std::string::size_type& pos, XmlTag& tag) {
    while (true) {
        auto at = xml.find('<', pos);
        if (at == std::string::npos) return false;
        const char* delimiter = nullptr;
        std::string::size_type prefix = 0;
        std::string::size_type suffix = 0;
        if (xml.compare(at, 4, "<!--") == 0) {
            delimiter = "-->"; prefix = 4; suffix = 3;
        } else if (xml.compare(at, 9, "<![CDATA[") == 0) {
            delimiter = "]]>"; prefix = 9; suffix = 3;
        } else if (xml.compare(at, 2, "<?") == 0) {
            delimiter = "?>"; prefix = 2; suffix = 2;
        }
        if (delimiter) {
            auto end = xml.find(delimiter, at + prefix);
            if (end == std::string::npos) throw std::runtime_error("unterminated XML text region");
            pos = end + suffix;
            continue;
        }
        auto end = tagEnd(xml, at);
        if (end == std::string::npos) throw std::runtime_error("unterminated XML tag");
        tag.at = at;
        tag.end = end;
        tag.closing = (at + 1 < end && xml[at + 1] == '/');
        tag.selfClosing = (xml[end - 1] == '/');
        auto nameAt = at + (tag.closing ? 2 : 1);
        auto nameEnd = nameAt;
        while (nameEnd < end && xml[nameEnd] != '/' &&
               !std::isspace(static_cast<unsigned char>(xml[nameEnd]))) ++nameEnd;
        tag.name = xml.substr(nameAt, nameEnd - nameAt);
        pos = end + 1;
        return true;
    }
}

// The caller selects an actual failure/error tag through nextTag. Keep its
// message and a whitespace-collapsed body excerpt, capped at 300 chars.
std::string extractFailureText(const std::string& inner) {
    std::string::size_type end = tagEnd(inner, 0);
    if (end == std::string::npos) return "";
    std::string tag = inner.substr(0, end + 1);
    std::string out = getAttr(tag, "message");
    if (end == 0 || inner[end - 1] != '/') {
        std::string::size_type close = inner.find("</", end);
        std::string body = (close == std::string::npos)
                               ? inner.substr(end + 1)
                               : inner.substr(end + 1, close - end - 1);
        std::string flat;
        bool space = true;  // collapse runs, trim leading
        for (char c : body) {
            bool ws = (c == ' ' || c == '\t' || c == '\n' || c == '\r');
            if (ws) {
                if (!space) {
                    flat.push_back(' ');
                    space = true;
                }
            } else {
                flat.push_back(c);
                space = false;
            }
        }
        while (!flat.empty() && flat.back() == ' ') flat.pop_back();
        if (flat.size() > 300) {
            flat.resize(300);
        }
        if (!out.empty() && !flat.empty()) out += " | ";
        out += flat;
    }
    if (out.size() > 500) out.resize(500);
    return out;
}

}  // namespace

JUnitReport parseJUnit(const std::string& xml) {
    JUnitReport report;
    std::string::size_type pos = 0;
    std::vector<std::string> suites;
    XmlTag current;
    while (nextTag(xml, pos, current)) {
        std::string tag = xml.substr(current.at, current.end - current.at + 1);
        if (current.name == "testsuite") {
            if (current.closing) {
                if (!suites.empty()) suites.pop_back();
            } else if (!current.selfClosing) {
                suites.push_back(getAttr(tag, "name"));
            }
            continue;
        }
        if (current.name != "testcase" || current.closing) continue;
        char status = 'P';
        auto failure = std::string::npos;
        auto error = std::string::npos;
        if (!current.selfClosing) {
            bool closed = false;
            while (nextTag(xml, pos, current)) {
                if (current.name == "testcase" && current.closing) {
                    closed = true;
                    break;
                }
                if (current.closing) continue;
                if (current.name == "failure" || current.name == "error") {
                    status = 'F';
                    auto& first = current.name == "failure" ? failure : error;
                    if (first == std::string::npos) first = current.at;
                } else if (current.name == "skipped" && status != 'F') {
                    status = 'S';
                }
            }
            if (!closed) throw std::runtime_error("unterminated JUnit testcase");
        }
        std::string classname = getAttr(tag, "classname");
        std::string name = getAttr(tag, "name");
        if (name.empty()) continue;  // unusable entry
        TestCaseResult tcRes;
        tcRes.id = junitIdentity(classname, name);
        tcRes.name = name;
        tcRes.classname = classname;
        tcRes.suites = suites;
        const std::string timeStr = getAttr(tag, "time");
        if (!timeStr.empty()) tcRes.timeMs = std::strtod(timeStr.c_str(), nullptr) * 1000.0;
        tcRes.status = status;
        if (status == 'F') {
            auto first = failure != std::string::npos ? failure : error;
            tcRes.failureText = extractFailureText(xml.substr(first, current.at - first));
            ++report.failed;
        } else if (status == 'S') {
            ++report.skipped;
        } else {
            ++report.passed;
        }
        report.cases.push_back(tcRes);
    }
    return report;
}

std::map<std::string, ResolvedJUnitTest> junitTestStatus(const std::vector<TestCaseResult>& cases) {
    using Identity = std::tuple<std::vector<std::string>, std::string, std::string>;
    std::map<std::string, std::map<Identity, char>> references;
    for (const TestCaseResult& tc : cases) {
        Identity identity{tc.suites, tc.classname, tc.name};
        auto add = [&](const std::string& ref) {
            auto& candidates = references[ref];
            auto it = candidates.find(identity);
            if (it == candidates.end()) {
                candidates.emplace(identity, tc.status);
            } else if (tc.status == 'F' || (tc.status == 'S' && it->second == 'P')) {
                it->second = tc.status;
            }
        };
        add(tc.name);
        add(tc.id);
        std::string suitePath;
        for (const std::string& suite : tc.suites) {
            if (suite.empty()) continue;
            if (!suitePath.empty()) suitePath += ".";
            suitePath += suite;
        }
        if (!suitePath.empty()) add(suitePath + "." + tc.id);
    }
    std::map<std::string, ResolvedJUnitTest> status;
    for (const auto& ref : references) {
        ResolvedJUnitTest resolved;
        if (ref.second.size() == 1) {
            const auto& candidate = *ref.second.begin();
            resolved.status = candidate.second;
            std::string id = junitIdentity(std::get<1>(candidate.first), std::get<2>(candidate.first));
            if (references.at(id).size() == 1) resolved.quarantineId = id;
        } else {
            resolved.status = 'A';
        }
        status[ref.first] = resolved;
    }
    return status;
}

}  // namespace tg
