#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/joox.h"
#include "utils/endian_helper.h"
#include "utils/paged_reader.h"

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

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
    using AES_ECB = CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption;
    static constexpr std::size_t kAESBlockSizeBits = 128; // AES-128-ECB
    static constexpr std::size_t kAESBlockSize = kAESBlockSizeBits / 16;
    static constexpr std::size_t kPlainBlockSize = 0x100000;                            // 1MiB
    static constexpr std::size_t kEncryptedBlockSize = kPlainBlockSize + kAESBlockSize; // padding (0x10, ...)

    std::array<uint8_t, CryptoPP::SHA1::DIGESTSIZE> key_{};

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

        AES_ECB aes{key_.data(), kAESBlockSize};
        bool io_ok{true};
        auto decrypt_ok = Reader{input}.WithPageSize(kEncryptedBlockSize, [&](size_t, uint8_t *buffer, size_t n) {
            if (n < kAESBlockSize || (n % kAESBlockSize != 0))
            {
                return false;
            }

            // Decrypt content
            aes.ProcessData(buffer, buffer, n);

            // Locate padding bytes
            const auto *p_padding_block = buffer + n - kAESBlockSize;
            uint8_t trim = p_padding_block[kAESBlockSize - 1];
            if (trim == 0 || trim > kAESBlockSize)
            {
                return false; // invalid pkcs5 padding
            }

            // Validate pkcs5 padding
            uint8_t zero_sum = 0;
            for (std::size_t i = kAESBlockSize - trim; i < kAESBlockSize; i++)
            {
                zero_sum |= p_padding_block[i] ^ trim;
            }

            if (zero_sum != 0)
            {
                return false; // pkcs5 padding validation failed
            }

            // Validation ok, resume.
            io_ok = output->Write(buffer, n - size_t{trim});
            return io_ok;
        });

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
