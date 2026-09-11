#pragma once

// Minimal JSON value model + parser/serializer (sufficient subset).
// Supports: null, bool, numbers (double), strings (with escapes incl. \u),
// arrays, objects. No comments, no trailing commas, no NaN/Infinity.

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace tg {

class JsonError : public std::runtime_error {
public:
    explicit JsonError(const std::string& msg) : std::runtime_error(msg) {}
};

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolean = false;
    double number = 0.0;
    std::string str;
    std::vector<JsonValue> array;
    std::map<std::string, JsonValue> object;

    static JsonValue makeNull() { return JsonValue(); }
    static JsonValue makeBool(bool b) {
        JsonValue v;
        v.type = Type::Bool;
        v.boolean = b;
        return v;
    }
    static JsonValue makeNumber(double d) {
        JsonValue v;
        v.type = Type::Number;
        v.number = d;
        return v;
    }
    static JsonValue makeString(const std::string& s) {
        JsonValue v;
        v.type = Type::String;
        v.str = s;
        return v;
    }
    static JsonValue makeArray() {
        JsonValue v;
        v.type = Type::Array;
        return v;
    }
    static JsonValue makeObject() {
        JsonValue v;
        v.type = Type::Object;
        return v;
    }

    bool isNull() const { return type == Type::Null; }
    bool isBool() const { return type == Type::Bool; }
    bool isNumber() const { return type == Type::Number; }
    bool isString() const { return type == Type::String; }
    bool isArray() const { return type == Type::Array; }
    bool isObject() const { return type == Type::Object; }

    bool has(const std::string& key) const {
        if (type != Type::Object) return false;
        return object.find(key) != object.end();
    }

    // Throws JsonError when missing or wrong type.
    const JsonValue& at(const std::string& key) const;
    const JsonValue& atIndex(std::size_t i) const;

    std::string getString(const std::string& key, const std::string& dflt) const;
    bool getBool(const std::string& key, bool dflt) const;
    double getNumber(const std::string& key, double dflt) const;
};

JsonValue parseJson(const std::string& text);  // throws JsonError
std::string toJson(const JsonValue& v, bool pretty = false);

}  // namespace tg
