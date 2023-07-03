#include "utils/base64.h"
#include "utils/defer.hpp"

#include <array>
#include <cstdint>
#include <vector>

#include <openssl/evp.h>

namespace parakeet_crypto::utils
{

constexpr int kBase64TextBlockLen = 4;
constexpr int kBase64RawBlockLen = 3;

std::vector<uint8_t> Base64Encode(const uint8_t *input, size_t len)
{
    auto len_mod3 = len % kBase64RawBlockLen;
    std::vector<uint8_t> result(len / kBase64RawBlockLen * kBase64TextBlockLen + kBase64RawBlockLen);
    auto actual_len = EVP_EncodeBlock(result.data(), input, static_cast<int>(len));
    result.resize(actual_len);

    if (len_mod3 == 1)
    {
        // There are 2 nil bytes to convert
        result[actual_len - 1] = '=';
        result[actual_len - 2] = '=';
    }
    else if (len_mod3 == 2)
    {
        // There is a single nil byte to convert
        result[actual_len - 1] = '=';
    }

    return result;
}

std::vector<uint8_t> Base64Decode(const uint8_t *input, size_t len)
{
    auto len_mod4 = len % kBase64TextBlockLen;
    std::vector<uint8_t> result(len / kBase64TextBlockLen * kBase64RawBlockLen + kBase64TextBlockLen);
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);

    Defer _cleanup([&]() { EVP_ENCODE_CTX_free(ctx); });

    int decoded_len{0};
    EVP_DecodeUpdate(ctx, result.data(), &decoded_len, input, static_cast<int>(len));
    if (decoded_len < 0)
    {
        return {};
    }

    // Recover missing bytes, when input is not aligned properly:
    int decode_block_len{0};
    if (len_mod4 != 0)
    {
        std::array<uint8_t, 3> buffer{'=', '=', '='};
        int padding_len = kBase64TextBlockLen - static_cast<int>(len_mod4);
        EVP_DecodeUpdate(ctx, &result.at(decoded_len), &decode_block_len, buffer.data(), padding_len);
        if (decode_block_len < 0)
        {
            return {};
        }
        decoded_len += decode_block_len;
    }

    if (EVP_DecodeFinal(ctx, &result.at(decoded_len), &decode_block_len) < 0)
    {
        return {};
    }

    decoded_len += decode_block_len;
    result.resize(decoded_len);
    return result;
}

} // namespace parakeet_crypto::utils
