#pragma once

#include <cstdint>

#include <algorithm>
#include <span>

namespace parakeet_crypto::utils {

template <typename... Args>
std::string Format(const char* fmt, Args... args) {
    auto text_len = std::snprintf(nullptr, 0, fmt, args...);
    if (text_len < 0) return "";

    // String contains the extra '\x00' at the end.
    std::string formatted(text_len, 0);
    std::snprintf(formatted.data(), text_len + 1, fmt, args...);
    return formatted;
}

}  // namespace parakeet_crypto::utils
