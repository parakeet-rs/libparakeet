#include "parakeet-crypto/transformer/migu3d.h"
#include "migu3d/freq_analysis.hpp"
#include "migu3d/migu_decrypt.hpp"
#include "parakeet-crypto/IStream.h"

#include "parakeet-crypto/ITransformer.h"
#include "utils/logger.h"
#include "utils/md5.h"
#include "utils/paged_reader.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace parakeet_crypto::transformer
{

class Migu3DTransformer final : public ITransformer
{
  private:
    static constexpr std::size_t kSaltSize = 16;
    static constexpr std::size_t kFileKeySize = 16;
    static constexpr std::size_t kFinalKeySize = migu3d::kMiguFinalKeySize;

    std::array<uint8_t, kFinalKeySize> key_{};

  public:
    Migu3DTransformer() = default;
    Migu3DTransformer(const uint8_t *salt, const uint8_t *file_key)
    {
        std::array<uint8_t, kSaltSize + kFileKeySize> input{};
        std::copy_n(salt, kSaltSize, input.begin());
        std::copy_n(file_key, kFileKeySize, input.begin() + kSaltSize);
        auto digest = utils::md5(input.data(), input.size());

        OPENSSL_buf2hexstr_ex(reinterpret_cast<char *>(key_.data()), key_.size(), // NOLINT(*-reinterpret-cast)
                              nullptr, digest.data(), digest.size(), 0);

        if (logger::DEBUG_Enabled)
        {
            std::string key_str(key_.begin(), key_.end());
            logger::DEBUG() << "Migu3D key: " << key_str;
        }
    }

    const char *GetName() override
    {
        return "Migu3D";
    }

    TransformResult Transform(IWriteable *output, IReadSeekable *input) override
    {
        std::array<uint8_t, kFinalKeySize> key = key_;
        if (auto keyless = key[0] == 0; keyless)
        {
            std::array<uint8_t, migu3d::kMiguFreqAnalysisSize> segment{};
            if (!input->ReadExact(segment.data(), migu3d::kMiguFreqAnalysisSize))
            {
                return TransformResult::ERROR_INSUFFICIENT_INPUT;
            }

            auto key_found = migu3d::SearchByFreqAnalysis(segment.data(), migu3d::kMiguFreqAnalysisSize);
            if (!key_found.has_value())
            {
                return TransformResult::ERROR_INVALID_FORMAT;
            }
            key = key_found.value();
            if (logger::DEBUG_Enabled)
            {
                std::string key_str(key.begin(), key.end());
                logger::DEBUG() << "Migu3D key recovered by freq analysis: " << key_str;
            }
            migu3d::DecryptSegment(segment.data(), segment.size(), 0, key.data());
            if (!output->Write(segment.data(), segment.size()))
            {
                return TransformResult::ERROR_IO_OUTPUT_UNKNOWN;
            }
        }

        auto decrypt_ok = utils::PagedReader{input}.ReadInPages([&](size_t offset, uint8_t *buffer, size_t n) {
            migu3d::DecryptSegment(buffer, n, offset, key.data());
            return output->Write(buffer, n);
        });

        return decrypt_ok ? TransformResult::OK : TransformResult::ERROR_INSUFFICIENT_OUTPUT;
    }
};

std::unique_ptr<ITransformer> CreateMiguTransformer(const uint8_t *salt, const uint8_t *file_key)
{
    return std::make_unique<Migu3DTransformer>(salt, file_key);
}

/**
 * @brief Migu3D transformer (keyless)
 *
 * @return std::unique_ptr<ITransformer>
 */
std::unique_ptr<ITransformer> CreateKeylessMiguTransformer()
{
    return std::make_unique<Migu3DTransformer>();
}

} // namespace parakeet_crypto::transformer
