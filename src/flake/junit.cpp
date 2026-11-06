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

bool xmlSpace(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

// XML attributes use character values, not their serialized spellings. Decode
// the predefined entities and numeric references once; custom entities are not
// supported by this scanner and must not silently create different identities.
std::string attributeValue(const std::string& raw) {
    std::string out;
    for (std::size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c != '&') {
            if (c == '<' || (static_cast<unsigned char>(c) < 0x20 && !xmlSpace(c)))
                throw std::runtime_error("invalid XML attribute character");
            if (c == '\r' && i + 1 < raw.size() && raw[i + 1] == '\n') ++i;
            out += xmlSpace(c) ? ' ' : c;
            continue;
        }
        auto end = raw.find(';', i + 1);
        if (end == std::string::npos) throw std::runtime_error("unterminated XML character reference");
        const std::string ref = raw.substr(i + 1, end - i - 1);
        unsigned int cp = 0;
        if (ref == "amp") cp = '&';
        else if (ref == "lt") cp = '<';
        else if (ref == "gt") cp = '>';
        else if (ref == "quot") cp = '"';
        else if (ref == "apos") cp = '\'';
        else if (!ref.empty() && ref[0] == '#') {
            std::size_t digit = 1;
            unsigned int base = 10;
            if (digit < ref.size() && ref[digit] == 'x') { base = 16; ++digit; }
            if (digit == ref.size()) throw std::runtime_error("empty XML character reference");
            for (; digit < ref.size(); ++digit) {
                char d = ref[digit];
                unsigned int value = d >= '0' && d <= '9' ? static_cast<unsigned int>(d - '0') :
                    d >= 'a' && d <= 'f' ? static_cast<unsigned int>(d - 'a' + 10) :
                    d >= 'A' && d <= 'F' ? static_cast<unsigned int>(d - 'A' + 10) : base;
                if (value >= base || cp > (0x10ffffU - value) / base)
                    throw std::runtime_error("invalid XML character reference");
                cp = cp * base + value;
            }
        } else {
            throw std::runtime_error("unsupported XML character reference");
        }
        if (!(cp == 9 || cp == 10 || cp == 13 || (cp >= 0x20 && cp <= 0xd7ff) ||
              (cp >= 0xe000 && cp <= 0xfffd) || (cp >= 0x10000 && cp <= 0x10ffff)))
            throw std::runtime_error("invalid XML character reference");
        if (cp <= 0x7f) out += static_cast<char>(cp);
        else if (cp <= 0x7ff) {
            out += static_cast<char>(0xc0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3f));
        } else if (cp <= 0xffff) {
            out += static_cast<char>(0xe0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (cp & 0x3f));
        } else {
            out += static_cast<char>(0xf0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (cp & 0x3f));
        }
        i = end;
    }
    return out;
}

// Walk complete quoted attributes, accepting XML whitespace around '='. Never
// look for an attribute name inside another attribute's quoted value.
std::string getAttr(const std::string& tag, const std::string& name) {
    std::size_t pos = 1;
    while (pos < tag.size() && !xmlSpace(tag[pos]) && tag[pos] != '>' && tag[pos] != '/') ++pos;
    std::string result;
    bool found = false;
    while (pos < tag.size()) {
        const auto beforeSpace = pos;
        while (pos < tag.size() && xmlSpace(tag[pos])) ++pos;
        if (pos == tag.size() || tag[pos] == '>' || tag[pos] == '/') break;
        if (pos == beforeSpace) throw std::runtime_error("missing XML attribute separator");
        const auto start = pos;
        while (pos < tag.size() && !xmlSpace(tag[pos]) && tag[pos] != '=' && tag[pos] != '>' && tag[pos] != '/') ++pos;
        const std::string key = tag.substr(start, pos - start);
        while (pos < tag.size() && xmlSpace(tag[pos])) ++pos;
        if (key.empty() || pos == tag.size() || tag[pos++] != '=')
            throw std::runtime_error("invalid XML attribute");
        while (pos < tag.size() && xmlSpace(tag[pos])) ++pos;
        if (pos == tag.size() || (tag[pos] != '\'' && tag[pos] != '"'))
            throw std::runtime_error("unquoted XML attribute");
        char quote = tag[pos++];
        auto end = tag.find(quote, pos);
        if (end == std::string::npos) throw std::runtime_error("unterminated XML attribute");
        if (key == name) {
            if (found) throw std::runtime_error("duplicate XML attribute");
            result = attributeValue(tag.substr(pos, end - pos));
            found = true;
        }
        pos = end + 1;
    }
    return result;
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
