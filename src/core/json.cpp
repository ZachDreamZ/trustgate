#include "core/json.h"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <sstream>

namespace tg {
namespace {

class Parser {
public:
    explicit Parser(const std::string& text) : s_(text), pos_(0) {}

    JsonValue run() {
        skipWs();
        JsonValue v = parseValue();
        skipWs();
        if (pos_ != s_.size()) fail("trailing characters after JSON value");
        return v;
    }

private:
    const std::string& s_;
    std::size_t pos_;

    [[noreturn]] void fail(const std::string& msg) {
        throw JsonError("JSON parse error at byte " + std::to_string(pos_) + ": " + msg);
    }

    void skipWs() {
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    char peek() {
        if (pos_ >= s_.size()) fail("unexpected end of input");
        return s_[pos_];
    }

    char take() {
        char c = peek();
        ++pos_;
        return c;
    }

    void expect(char c) {
        if (take() != c) fail(std::string("expected '") + c + "'");
    }

    void expectWord(const char* word) {
        for (const char* p = word; *p; ++p) {
            if (pos_ >= s_.size() || s_[pos_] != *p) {
                fail(std::string("expected '") + word + "'");
            }
            ++pos_;
        }
    }

    static void encodeUtf8(std::string& out, unsigned long cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    unsigned long parseHex4() {
        if (pos_ + 4 > s_.size()) fail("truncated \\u escape");
        unsigned long cp = 0;
        for (int i = 0; i < 4; ++i) {
            char c = s_[pos_++];
            cp <<= 4;
            if (c >= '0' && c <= '9') {
                cp |= static_cast<unsigned long>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                cp |= static_cast<unsigned long>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                cp |= static_cast<unsigned long>(c - 'A' + 10);
            } else {
                fail("invalid hex digit in \\u escape");
            }
        }
        return cp;
    }

    JsonValue parseValue() {
        char c = peek();
        if (c == '{') return parseObject();
        if (c == '[') return parseArray();
        if (c == '"') {
            JsonValue v = JsonValue::makeString(parseString());
            return v;
        }
        if (c == 't') {
            expectWord("true");
            return JsonValue::makeBool(true);
        }
        if (c == 'f') {
            expectWord("false");
            return JsonValue::makeBool(false);
        }
        if (c == 'n') {
            expectWord("null");
            return JsonValue::makeNull();
        }
        if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
        fail("unexpected character");
    }

    JsonValue parseObject() {
        JsonValue obj = JsonValue::makeObject();
        expect('{');
        skipWs();
        if (peek() == '}') {
            ++pos_;
            return obj;
        }
        while (true) {
            skipWs();
            if (peek() != '"') fail("expected string key in object");
            std::string key = parseString();
            skipWs();
            expect(':');
            skipWs();
            obj.object[key] = parseValue();
            skipWs();
            char c = take();
            if (c == '}') break;
            if (c != ',') fail("expected ',' or '}' in object");
        }
        return obj;
    }

    JsonValue parseArray() {
        JsonValue arr = JsonValue::makeArray();
        expect('[');
        skipWs();
        if (peek() == ']') {
            ++pos_;
            return arr;
        }
        while (true) {
            skipWs();
            arr.array.push_back(parseValue());
            skipWs();
            char c = take();
            if (c == ']') break;
            if (c != ',') fail("expected ',' or ']' in array");
        }
        return arr;
    }

    std::string parseString() {
        expect('"');
        std::string out;
        while (true) {
            if (pos_ >= s_.size()) fail("unterminated string");
            char c = s_[pos_++];
            if (c == '"') break;
            if (c == '\\') {
                if (pos_ >= s_.size()) fail("truncated escape");
                char e = s_[pos_++];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        unsigned long cp = parseHex4();
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            // High surrogate: expect a low surrogate.
                            if (pos_ + 6 <= s_.size() && s_[pos_] == '\\' &&
                                s_[pos_ + 1] == 'u') {
                                pos_ += 2;
                                unsigned long lo = parseHex4();
                                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                } else {
                                    fail("invalid low surrogate");
                                }
                            } else {
                                fail("unpaired high surrogate");
                            }
                        }
                        encodeUtf8(out, cp);
                        break;
                    }
                    default: fail("invalid escape character");
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    JsonValue parseNumber() {
        std::size_t start = pos_;
        if (peek() == '-') ++pos_;
        while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) {
            ++pos_;
        }
        if (pos_ < s_.size() && s_[pos_] == '.') {
            ++pos_;
            while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) {
                ++pos_;
            }
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) {
                ++pos_;
            }
        }
        double d = std::strtod(s_.c_str() + start, nullptr);
        if (!std::isfinite(d)) fail("non-finite number");
        return JsonValue::makeNumber(d);
    }
};

void writeEscaped(std::string& out, const std::string& s) {
    out.push_back('"');
    char buf[8];
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

void writeValue(std::string& out, const JsonValue& v, bool pretty, int indent) {
    switch (v.type) {
        case JsonValue::Type::Null: out += "null"; break;
        case JsonValue::Type::Bool: out += v.boolean ? "true" : "false"; break;
        case JsonValue::Type::Number: {
            std::ostringstream oss;
            oss.precision(17);
            oss << v.number;
            out += oss.str();
            break;
        }
        case JsonValue::Type::String: writeEscaped(out, v.str); break;
        case JsonValue::Type::Array: {
            out.push_back('[');
            for (std::size_t i = 0; i < v.array.size(); ++i) {
                if (i) out.push_back(',');
                if (pretty) {
                    out.push_back('\n');
                    out.append(static_cast<std::size_t>(indent + 1) * 2, ' ');
                }
                writeValue(out, v.array[i], pretty, indent + 1);
            }
            if (pretty && !v.array.empty()) {
                out.push_back('\n');
                out.append(static_cast<std::size_t>(indent) * 2, ' ');
            }
            out.push_back(']');
            break;
        }
        case JsonValue::Type::Object: {
            out.push_back('{');
            bool first = true;
            for (const auto& kv : v.object) {
                if (!first) out.push_back(',');
                first = false;
                if (pretty) {
                    out.push_back('\n');
                    out.append(static_cast<std::size_t>(indent + 1) * 2, ' ');
                }
                writeEscaped(out, kv.first);
                out.push_back(':');
                if (pretty) out.push_back(' ');
                writeValue(out, kv.second, pretty, indent + 1);
            }
            if (pretty && !v.object.empty()) {
                out.push_back('\n');
                out.append(static_cast<std::size_t>(indent) * 2, ' ');
            }
            out.push_back('}');
            break;
        }
    }
}

}  // namespace

const JsonValue& JsonValue::at(const std::string& key) const {
    if (type != Type::Object) throw JsonError("at('" + key + "'): not an object");
    auto it = object.find(key);
    if (it == object.end()) throw JsonError("missing key '" + key + "'");
    return it->second;
}

const JsonValue& JsonValue::atIndex(std::size_t i) const {
    if (type != Type::Array) throw JsonError("atIndex: not an array");
    if (i >= array.size()) throw JsonError("array index out of range");
    return array[i];
}

std::string JsonValue::getString(const std::string& key, const std::string& dflt) const {
    if (type != Type::Object) return dflt;
    auto it = object.find(key);
    if (it == object.end() || !it->second.isString()) return dflt;
    return it->second.str;
}

bool JsonValue::getBool(const std::string& key, bool dflt) const {
    if (type != Type::Object) return dflt;
    auto it = object.find(key);
    if (it == object.end() || !it->second.isBool()) return dflt;
    return it->second.boolean;
}

double JsonValue::getNumber(const std::string& key, double dflt) const {
    if (type != Type::Object) return dflt;
    auto it = object.find(key);
    if (it == object.end() || !it->second.isNumber()) return dflt;
    return it->second.number;
}

JsonValue parseJson(const std::string& text) {
    Parser p(text);
    return p.run();
}

std::string toJson(const JsonValue& v, bool pretty) {
    std::string out;
    writeValue(out, v, pretty, 0);
    return out;
}

}  // namespace tg
