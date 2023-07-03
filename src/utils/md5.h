#pragma once

#include <array>

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::utils
{

constexpr std::size_t MD5_DIGEST_SIZE = 16;

std::array<uint8_t, MD5_DIGEST_SIZE> md5(const uint8_t *data, size_t len);

inline std::array<uint8_t, MD5_DIGEST_SIZE> md5_str(const char *str, size_t len)
{
    return md5(reinterpret_cast<const uint8_t *>(str), len); // NOLINT(*-reinterpret-cast)
}

inline std::array<uint8_t, MD5_DIGEST_SIZE> md5_str(const char *str)
{
    const char *p_end = str;
    while (*p_end != 0)
    {
        p_end++;
    }

    return md5_str(str, p_end - str);
}

} // namespace parakeet_crypto::utils
