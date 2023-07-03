#include "kgm/kgm_header.h"
#include "kgm_crypto.h"
#include "parakeet-crypto/transformer/kgm.h"
#include "utils/base64.h"
#include "utils/hex.h"
#include "utils/loop_iterator.h"
#include "utils/md5.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>

namespace parakeet_crypto::kgm
{

class KGMCryptoType4 final : public IKGMCrypto
{
  private:
    static constexpr size_t V4_DIGEST_SIZE = 31;
    std::vector<uint8_t> slot_key_;
    std::vector<uint8_t> file_key_;

    static inline std::array<uint8_t, V4_DIGEST_SIZE> hash_type4(const uint8_t *data, size_t len)
    {
        static constexpr std::array<size_t, V4_DIGEST_SIZE> kDigestIndexes = {
            0x05, 0x0e, 0x0d, 0x02, 0x0c, 0x0a, 0x0f, 0x0b, 0x03, 0x08, 0x05, 0x06, 0x09, 0x04, 0x03, 0x07,
            0x00, 0x0e, 0x0d, 0x06, 0x02, 0x0c, 0x0a, 0x0f, 0x01, 0x0b, 0x08, 0x07, 0x09, 0x04, 0x01,
        };

        auto digest = utils::md5(data, len);
        std::array<uint8_t, V4_DIGEST_SIZE> result{};
        for (int i = 0; i < V4_DIGEST_SIZE; i++)
        {
            result[i] = digest[kDigestIndexes[i]];
        }
        return result;
    }

    static std::vector<uint8_t> key_expansion(const std::vector<uint8_t> &table, //
                                              const uint8_t *key, size_t key_len)
    {
        size_t table_len = table.size();
        auto md5_final = hash_type4(key, key_len);
        auto final_key_size = 4 * (V4_DIGEST_SIZE - 1) * (table_len - 1);

        std::vector<uint8_t> expanded_key(final_key_size, 0);
        auto *p_key = expanded_key.data();
        for (uint32_t i = 1; i < V4_DIGEST_SIZE; i++)
        {
            auto temp1 = i * static_cast<uint32_t>(md5_final[i]);

            for (uint32_t j = 1; j < static_cast<uint32_t>(table_len); j++)
            {
                uint32_t temp = temp1 * j * static_cast<uint32_t>(table[j]);

                // NOLINTBEGIN (*-magic-numbers)
                *p_key++ = static_cast<uint8_t>(temp >> 0x00);
                *p_key++ = static_cast<uint8_t>(temp >> 0x18);
                *p_key++ = static_cast<uint8_t>(temp >> 0x10);
                *p_key++ = static_cast<uint8_t>(temp >> 0x08);
                // NOLINTEND (*-magic-numbers)
            }
        }

        assert((p_key - expanded_key.data()) == expanded_key.size()); // NOLINT

        return expanded_key;
    }

    inline void configure_slot_key(const transformer::KGMConfig &config, const std::vector<uint8_t> &slot_key)
    {
        using namespace parakeet_crypto::utils;
        auto slot_key_md5 = utils::md5(slot_key.data(), slot_key.size());
        auto md5_hex = utils::Hex(slot_key_md5.data(), slot_key_md5.size(), false);
        auto md5_b64 = utils::Base64Encode(md5_hex);
        slot_key_ = key_expansion(config.v4.slot_key_table, md5_b64.data(), md5_b64.size());
    }

    inline void configure_file_key(const transformer::KGMConfig &config, const FileHeader &header)
    {
        file_key_ = key_expansion(config.v4.file_key_table, &header.file_key[0], sizeof(header.file_key));
    }

  public:
    bool Configure(const transformer::KGMConfig &config, const std::vector<uint8_t> &slot_key,
                   const FileHeader &header) override
    {
        if (config.v4.slot_key_table.empty() || config.v4.file_key_table.empty())
        {
            return false;
        }

        configure_slot_key(config, slot_key);
        configure_file_key(config, header);
        return true;
    }

    template <bool IS_ENCRYPT> void EncryptDecrypt(uint64_t offset, uint8_t *buffer, size_t len)
    {
        utils::LoopIterator slot_key{slot_key_.data(), slot_key_.size(), static_cast<size_t>(offset)};
        utils::LoopIterator file_key{file_key_.data(), file_key_.size(),
                                     static_cast<size_t>(offset / slot_key_.size())};

        auto *end = buffer + len;
        for (auto *it = buffer; it < end; it++)
        {
            uint8_t offset_key = xor_u32_bytes(static_cast<uint32_t>(offset));

            auto v = *it; // NOLINT(readability-identifier-length)
            if constexpr (IS_ENCRYPT)
            {
                v ^= offset_key;
                v ^= slot_key.Get();
                v ^= v << 4;
                v ^= file_key.Get();
            }
            else
            {
                v ^= file_key.Get();
                v ^= v << 4;
                v ^= slot_key.Get();
                v ^= offset_key;
            }
            *it = v;

            offset++;
            if (slot_key.Next())
            {
                file_key.Next();
            }
        }
    }

    void Encrypt(uint64_t offset, uint8_t *buffer, size_t len) override
    {
        EncryptDecrypt<true>(offset, buffer, len);
    }

    void Decrypt(uint64_t offset, uint8_t *buffer, size_t len) override
    {
        EncryptDecrypt<false>(offset, buffer, len);
    }
};

std::unique_ptr<IKGMCrypto> CreateKGMCryptoType4()
{
    return std::make_unique<KGMCryptoType4>();
}

} // namespace parakeet_crypto::kgm
