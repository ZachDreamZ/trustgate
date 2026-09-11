#pragma once

// HMAC-SHA256 (RFC 2104) file attestation. Symmetric and offline: the same
// key signs and verifies, which fits CI audit trails (sign the verdict in
// one step, verify before consuming it in the next). This is origin
// authentication with a shared secret, NOT public-key signatures.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tg {

std::array<uint8_t, 32> hmacSha256(const uint8_t* key, std::size_t keyLen, const void* data,
                                   std::size_t len);

// File attestation MAC: HMAC-SHA256 over (filename + NUL + content), so the
// signature is cryptographically bound to the path it was issued for.
// Patching the recorded filename without the key invalidates the MAC.
std::string attestationMac(const std::vector<uint8_t>& key, const std::string& filename,
                           const std::string& content);

std::string toHex(const uint8_t* data, std::size_t len);
inline std::string toHex(const std::array<uint8_t, 32>& digest) {
    return toHex(digest.data(), digest.size());
}

// Parses even-length hex; false on any invalid digit or odd length.
bool fromHex(const std::string& hex, std::vector<uint8_t>& out);

// Constant-time equality for MAC comparison (no early exit on mismatch).
bool constantTimeEqual(const uint8_t* a, const uint8_t* b, std::size_t len);

// 32 random bytes as lowercase hex, for `--gen-key`.
std::string randomKeyHex();

struct KeyLoad {
    std::vector<uint8_t> bytes;
    std::string error;  // empty on success
};

// Exactly one of hex/file/env must be set. Keys shorter than 16 bytes are
// rejected as weak. Never logs key material (errors name the source only).
KeyLoad loadKey(const std::string& hex, const std::string& file, const std::string& env);

}  // namespace tg
