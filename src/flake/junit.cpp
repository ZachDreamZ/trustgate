#include "flake/junit.h"

#include <cctype>
#include <cstdlib>

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

bool hasChild(const std::string& inner, const std::string& child) {
    return inner.find("<" + child) != std::string::npos;
}

// message="..." of the first failure/error child plus a whitespace-collapsed
// excerpt of its body, capped at 300 chars. Empty when no such child exists.
std::string extractFailureText(const std::string& inner) {
    std::string::size_type at = inner.find("<failure");
    if (at == std::string::npos) at = inner.find("<error");
    if (at == std::string::npos) return "";
    std::string::size_type tagEnd = inner.find('>', at);
    if (tagEnd == std::string::npos) return "";
    std::string tag = inner.substr(at, tagEnd - at + 1);
    std::string out = getAttr(tag, "message");
    if (tagEnd == 0 || inner[tagEnd - 1] != '/') {
        std::string::size_type close = inner.find("</", tagEnd);
        std::string body = (close == std::string::npos)
                               ? inner.substr(tagEnd + 1)
                               : inner.substr(tagEnd + 1, close - tagEnd - 1);
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
    const std::string open = "<testcase";
    while (true) {
        std::string::size_type tc = xml.find(open, pos);
        if (tc == std::string::npos) break;
        // Avoid matching "<testcases" etc: next char must be space, '/', or '>'.
        std::string::size_type after = tc + open.size();
        if (after < xml.size()) {
            char c = xml[after];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '/' && c != '>') {
                pos = after;
                continue;
            }
        }
        std::string::size_type tagEnd = xml.find('>', after);
        if (tagEnd == std::string::npos) break;
        std::string tag = xml.substr(tc, tagEnd - tc + 1);
        bool selfClosing = (tagEnd > tc && xml[tagEnd - 1] == '/');
        std::string inner;
        std::string::size_type next = tagEnd + 1;
        if (!selfClosing) {
            std::string::size_type close = xml.find("</testcase>", next);
            if (close == std::string::npos) break;
            inner = xml.substr(next, close - next);
            next = close + std::string("</testcase>").size();
        }
        pos = next;

        std::string classname = getAttr(tag, "classname");
        std::string name = getAttr(tag, "name");
        if (name.empty()) continue;  // unusable entry
        TestCaseResult tcRes;
        tcRes.id = junitIdentity(classname, name);
        const std::string timeStr = getAttr(tag, "time");
        if (!timeStr.empty()) tcRes.timeMs = std::strtod(timeStr.c_str(), nullptr) * 1000.0;
        if (hasChild(inner, "failure") || hasChild(inner, "error")) {
            tcRes.status = 'F';
            tcRes.failureText = extractFailureText(inner);
            ++report.failed;
        } else if (hasChild(inner, "skipped")) {
            tcRes.status = 'S';
            ++report.skipped;
        } else {
            tcRes.status = 'P';
            ++report.passed;
        }
        report.cases.push_back(tcRes);
    }
    return report;
}

}  // namespace tg
