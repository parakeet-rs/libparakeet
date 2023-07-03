#include "utils/md5.h"

#include <algorithm>
#include <openssl/evp.h>

namespace parakeet_crypto::utils
{

std::array<uint8_t, MD5_DIGEST_SIZE> md5(const uint8_t *data, size_t len)
{
    std::array<uint8_t, MD5_DIGEST_SIZE> result{};
    std::array<uint8_t, EVP_MAX_MD_SIZE> digest{};

    static_assert(MD5_DIGEST_SIZE <= EVP_MAX_MD_SIZE, "md5 size digest size overflow");

    unsigned int digest_len{};
    EVP_MD_CTX *ctx_md5 = EVP_MD_CTX_new();

    EVP_DigestInit(ctx_md5, EVP_md5());
    EVP_DigestUpdate(ctx_md5, data, len);
    EVP_DigestFinal(ctx_md5, digest.data(), &digest_len);
    EVP_MD_CTX_free(ctx_md5);

    std::copy_n(digest.begin(), MD5_DIGEST_SIZE, result.begin());

    return result;
}

} // namespace parakeet_crypto::utils
