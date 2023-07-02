#pragma once
#include "ncm_rc4.h"

#include "parakeet-crypto/transformer/ncm.h"
#include "utils/pkcs7.hpp"

#include <algorithm>
#include <cstdint>
#include <openssl/types.h>
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

    std::vector<uint8_t> content_key;
    std::transform(file_key.cbegin(), file_key.cend(), file_key.begin(),
                   [&](auto key) { return key ^ kFileKeyXorKey; });

    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(aes_ctx, EVP_aes_128_ecb(), aes_key_bytes.data(), nullptr);

    std::vector<uint8_t> buff_decrypted(file_key.size() + EVP_CIPHER_CTX_get_block_size(aes_ctx));

    int plain_len = 0;
    int outl = 0;
    EVP_DecryptUpdate(aes_ctx, buff_decrypted.data(), &outl, file_key.data(), static_cast<int>(file_key.size()));
    plain_len += outl;
    EVP_DecryptFinal(aes_ctx, &buff_decrypted.at(plain_len), &outl);
    plain_len += outl;
    plain_len = utils::PKCS7_unpad(buff_decrypted.data(), plain_len);

    if (plain_len <= 0)
    {
        return {}; // could not decrypt the key.
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
