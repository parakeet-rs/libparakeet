#include "parakeet-crypto/transformer/migu3d.h"
#include "migu3d/freq_analysis.hpp"
#include "migu3d/migu_decrypt.hpp"
#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/utils/hex.h"
#include "utils/logger.h"
#include "utils/paged_reader.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "parakeet-crypto/utils/hash/md5.h"

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
        std::array<uint8_t, utils::hash::kMD5DigestSize> digest{};
        utils::hash::md5_ctx md5_ctx{};
        utils::hash::md5_init(&md5_ctx);
        utils::hash::md5_update(&md5_ctx, salt, kSaltSize);
        utils::hash::md5_update(&md5_ctx, file_key, kFileKeySize);
        utils::hash::md5_final(&md5_ctx, digest.data());

        auto key = utils::Hex(digest.data(), digest.size());
        std::copy(key.cbegin(), key.cend(), key_.begin());

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
