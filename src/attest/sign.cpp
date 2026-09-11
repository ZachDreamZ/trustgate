#include "attest/sign.h"

#include <cstdlib>
#include <random>

#include "attest/sha256.h"
#include "core/fsutil.h"

namespace tg {
namespace {

std::string trimWs(const std::string& s) {
    std::string::size_type a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    std::string::size_type b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

}  // namespace

std::array<uint8_t, 32> hmacSha256(const uint8_t* key, std::size_t keyLen, const void* data,
                                   std::size_t len) {
    // Keys longer than the block size hash down first (RFC 2104 section 2).
    std::array<uint8_t, 32> keyHash{};
    const uint8_t* k = key;
    std::size_t kLen = keyLen;
    if (kLen > 64) {
        keyHash = sha256(key, keyLen);
        k = keyHash.data();
        kLen = keyHash.size();
    }
    uint8_t padded[64] = {};
    for (std::size_t i = 0; i < kLen; ++i) padded[i] = k[i];
    uint8_t inner[64], outer[64];
    for (int i = 0; i < 64; ++i) {
        inner[i] = padded[i] ^ 0x36;
        outer[i] = padded[i] ^ 0x5c;
    }
    // inner = SHA256(innerPad || message)
    std::string innerMsg(reinterpret_cast<const char*>(inner), 64);
    innerMsg.append(static_cast<const char*>(data), len);
    std::array<uint8_t, 32> innerHash = sha256(innerMsg);
    // HMAC = SHA256(outerPad || inner)
    std::string outerMsg(reinterpret_cast<const char*>(outer), 64);
    outerMsg.append(reinterpret_cast<const char*>(innerHash.data()), innerHash.size());
    return sha256(outerMsg);
}

std::string toHex(const uint8_t* data, std::size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[(data[i] >> 4) & 0xF]);
        out.push_back(digits[data[i] & 0xF]);
    }
    return out;
}

bool fromHex(const std::string& hex, std::vector<uint8_t>& out) {
    out.clear();
    if (hex.empty() || hex.size() % 2 != 0) return false;
    auto nibble = [](char c, uint8_t& v) {
        if (c >= '0' && c <= '9') {
            v = static_cast<uint8_t>(c - '0');
            return true;
        }
        if (c >= 'a' && c <= 'f') {
            v = static_cast<uint8_t>(c - 'a' + 10);
            return true;
        }
        if (c >= 'A' && c <= 'F') {
            v = static_cast<uint8_t>(c - 'A' + 10);
            return true;
        }
        return false;
    };
    for (std::string::size_type i = 0; i < hex.size(); i += 2) {
        uint8_t hi = 0, lo = 0;
        if (!nibble(hex[i], hi) || !nibble(hex[i + 1], lo)) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

bool constantTimeEqual(const uint8_t* a, const uint8_t* b, std::size_t len) {
    // No early exit: every byte is always compared. volatile prevents the
    // compiler from shortcutting the accumulation loop.
    volatile uint8_t diff = 0;
    for (std::size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

std::string attestationMac(const std::vector<uint8_t>& key, const std::string& filename,
                           const std::string& content) {
    std::string body = filename;
    body.push_back('\0');
    body += content;
    return toHex(hmacSha256(key.data(), key.size(), body.data(), body.size()));
}

std::string randomKeyHex() {
    std::random_device rd;
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i) {
        uint8_t byte = static_cast<uint8_t>(rd() & 0xFF);
        out += toHex(&byte, 1);
    }
    return out;
}

KeyLoad loadKey(const std::string& hex, const std::string& file, const std::string& env) {
    KeyLoad kl;
    int set = 0;
    if (!hex.empty()) ++set;
    if (!file.empty()) ++set;
    if (!env.empty()) ++set;
    if (set == 0) {
        kl.error = "no key provided (need one of --key, --key-file, --key-env)";
        return kl;
    }
    if (set > 1) {
        kl.error = "only one of --key, --key-file, --key-env may be set";
        return kl;
    }
    std::string raw;
    if (!hex.empty()) {
        raw = hex;
    } else if (!file.empty()) {
        try {
            raw = trimWs(readFile(file));
        } catch (const std::exception&) {
            kl.error = "cannot read key file: " + file;
            return kl;
        }
    } else {
        const char* val = std::getenv(env.c_str());
        if (val == nullptr || *val == '\0') {
            kl.error = "key env var not set: " + env;
            return kl;
        }
        raw = trimWs(val);
    }
    if (!fromHex(raw, kl.bytes)) {
        kl.error = "key is not valid even-length hex";
        return kl;
    }
    if (kl.bytes.size() < 16) {
        kl.error = "key too short (need >= 16 bytes hex)";
        kl.bytes.clear();
        return kl;
    }
    if (kl.bytes.size() > 128) {
        kl.error = "key too long (max 128 bytes hex)";
        kl.bytes.clear();
        return kl;
    }
    return kl;
}

}  // namespace tg
