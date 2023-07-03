#pragma once
#include "ncm_rc4.h"

#include "parakeet-crypto/transformer/ncm.h"
#include "utils/pkcs7.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

#include <openssl/evp.h>

namespace parakeet_crypto::transformer
{

static constexpr size_t kNCMFinalKeyLen = 0x100;
inline std::optional<std::array<uint8_t, kNCMFinalKeyLen>> DecryptNCMAudioKey(
    std::vector<uint8_t> &file_key, const std::array<uint8_t, kNCMContentKeySize> &aes_key_bytes)
{
    constexpr uint8_t kFileKeyXorKey{0x64};

    std::transform(file_key.cbegin(), file_key.cend(), file_key.begin(),
                   [&](auto key) { return key ^ kFileKeyXorKey; });

    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(aes_ctx, EVP_aes_128_ecb(), aes_key_bytes.data(), nullptr);

    std::vector<uint8_t> content_key(file_key.size() + EVP_CIPHER_CTX_get_block_size(aes_ctx));

    int content_key_len = 0;
    int outl = 0;
    int ok{1}; // NOLINT(readability-identifier-length)
    ok &= EVP_DecryptUpdate(aes_ctx, content_key.data(), &outl, file_key.data(), static_cast<int>(file_key.size()));
    content_key_len += outl;
    ok &= EVP_DecryptFinal(aes_ctx, &content_key.at(content_key_len), &outl);
    EVP_CIPHER_CTX_free(aes_ctx);
    content_key_len += outl;
    content_key.resize(content_key_len);

    if (ok != 1 || content_key_len <= 0)
    {
        return {}; // could not decrypt the key, or padding validation had failed
    }

    constexpr static std::array<const uint8_t, 17> kContentKeyPrefix{'n', 'e', 't', 'e', 'a', 's', 'e', 'c', 'l',
                                                                     'o', 'u', 'd', 'm', 'u', 's', 'i', 'c'};

    if (!std::equal(kContentKeyPrefix.cbegin(), kContentKeyPrefix.cend(), content_key.cbegin()))
    {
        return {};
    }

    NeteaseRC4 rc4(&content_key.at(kContentKeyPrefix.size()), content_key.size() - kContentKeyPrefix.size());
    std::array<uint8_t, kNCMFinalKeyLen> key{};
    for (auto it = key.begin(); it < key.end(); it++) // NOLINT(readability-qualified-auto)
    {
        *it = rc4.Next();
    }

    return key;
}

} // namespace parakeet_crypto::transformer
