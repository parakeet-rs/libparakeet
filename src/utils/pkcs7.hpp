#pragma once

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::utils
{

template <size_t const BLOCK_SIZE = 0> inline int PKCS7_unpad(const uint8_t *data, size_t data_len)
{
    if (data_len == 0)
    {
        return 0; // buff too small
    }

    uint8_t trim = data[data_len - 1];
    if (trim == 0 || static_cast<size_t>(trim) >= data_len)
    {
        return -1; // Invalid padding length
    }

    if constexpr (BLOCK_SIZE != 0)
    {
        if (static_cast<size_t>(trim) > BLOCK_SIZE)
        {
            return -3; // padding larger than block size
        }
    }

    size_t unpadded_len = data_len - trim;
    uint8_t pad_verify{0}; // expect to be zero
    const uint8_t *ptr = &data[unpadded_len];
    const uint8_t *end = &data[data_len];
    while (ptr < end)
    {
        pad_verify |= *ptr++ ^ trim;
    }

    if (pad_verify != 0)
    {
        return -2; // some padding bytes mismatch
    }

    return static_cast<int>(unpadded_len);
}

template <size_t const BLOCK_SIZE = 0, typename Container> inline int PKCS7_unpad(Container &&data)
{
    return PKCS7_unpad<BLOCK_SIZE>(data.data(), data.size());
}

} // namespace parakeet_crypto::utils
