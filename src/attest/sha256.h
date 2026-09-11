#pragma once

// FIPS 180-4 SHA-256, stdlib-only. Returns the 32-byte digest.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace tg {

std::array<uint8_t, 32> sha256(const void* data, std::size_t len);

inline std::array<uint8_t, 32> sha256(const std::string& s) {
    return sha256(s.data(), s.size());
}

}  // namespace tg
