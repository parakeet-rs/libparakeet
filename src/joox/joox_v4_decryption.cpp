#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/joox.h"
#include "utils/endian_helper.h"
#include "utils/paged_reader.h"
#include "utils/pkcs7.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace parakeet_crypto::transformer
{

class JooxDecryptionV4Transformer final : public ITransformer
{
  private:
    static constexpr size_t kAESBlockSizeBits = 128; // AES-128-ECB
    static constexpr size_t kAESBlockSize = kAESBlockSizeBits / 8;
    static constexpr size_t kPlainBlockSize = 0x100000;                            // 1MiB
    static constexpr size_t kEncryptedBlockSize = kPlainBlockSize + kAESBlockSize; // padding (0x10, ...)

    std::array<uint8_t, kAESBlockSize> key_{};

    inline void SetupKey(JooxConfig &config)
    {
        constexpr size_t kDeriveIteration = 1000;
        PKCS5_PBKDF2_HMAC_SHA1(config.install_uuid.c_str(), static_cast<int>(config.install_uuid.size()), //
                               config.salt.data(), static_cast<int>(config.salt.size()),                  //
                               kDeriveIteration,                                                          //
                               static_cast<int>(key_.size()), key_.data());
    }

  public:
    JooxDecryptionV4Transformer(JooxConfig config)
    {
        SetupKey(config);
    }

    const char *GetName() override
    {
        return "JOOX (Dv4)";
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        constexpr std::size_t kVer4HeaderSize = 12; /* 'E!04' + uint64_t_be(file size) */
        constexpr static std::array<uint8_t, 4> kMagicHeader{'E', '!', '0', '4'};

        std::array<uint8_t, kVer4HeaderSize> header{};
        if (!input->ReadExact(header.data(), header.size()))
        {
            return TransformResult::ERROR_INSUFFICIENT_INPUT;
        }
        if (!std::equal(kMagicHeader.begin(), kMagicHeader.end(), header.begin()))
        {
            return TransformResult::ERROR_INVALID_FORMAT;
        }

        // auto actual_size = ReadBigEndian<uint64_t>(&header.at(4)); // is this used?

        using Reader = utils::PagedReader;

        EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit(aes_ctx, EVP_aes_128_ecb(), key_.data(), nullptr);

        // disable padding, so we can avoid re-init aes-128-ecb.
        EVP_CIPHER_CTX_set_padding(aes_ctx, 0);

        bool io_ok{true};
        auto decrypt_ok = Reader{input}.WithPageSize(kEncryptedBlockSize, [&](size_t, uint8_t *buffer, size_t n) {
            if (n == 0 || (n % kAESBlockSize != 0))
            {
                return false; // we should have at least 1 full block, in blocks.
            }

            int n_updated{};
            if (EVP_DecryptUpdate(aes_ctx, buffer, &n_updated, buffer, static_cast<int>(n)) == 0)
            {
                return false; // aes decryption failed?!
            }

            // Locate padding bytes
            auto n_actual = utils::PKCS7_unpad(buffer, n_updated);
            if (n_actual <= 0)
            {
                return false; // not padded correctly?
            }

            // Validation ok, resume.
            io_ok = output->Write(buffer, n_actual);
            return io_ok;
        });

        EVP_CIPHER_CTX_free(aes_ctx);

        return decrypt_ok ? TransformResult::OK
               : io_ok    ? TransformResult::ERROR_INVALID_KEY
                          : TransformResult::ERROR_IO_OUTPUT_UNKNOWN;
    }
};

std::unique_ptr<ITransformer> CreateJooxDecryptionV4Transformer(JooxConfig config)
{
    return std::make_unique<JooxDecryptionV4Transformer>(std::move(config));
}

} // namespace parakeet_crypto::transformer
