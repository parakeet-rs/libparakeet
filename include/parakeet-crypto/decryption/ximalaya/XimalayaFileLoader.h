#pragma once

#include "parakeet-crypto/decryption/DecryptionStream.h"

#include <array>
#include <span>

namespace parakeet_crypto::decryption::ximalaya {

constexpr std::size_t kX2MContentKeySize = 0x04;
constexpr std::size_t kX3MContentKeySize = 0x20;
constexpr std::size_t kScrambleTableSize = 0x400;

typedef std::array<uint8_t, kX2MContentKeySize> X2MContentKey;
typedef std::array<uint8_t, kX3MContentKeySize> X3MContentKey;
typedef std::array<uint16_t, kScrambleTableSize> ScrambleTable;
typedef std::span<uint8_t> XmlyContentKey;

class XimalayaFileLoader : public DecryptionStream {
 public:
  virtual const std::string GetName() const override { return "Ximalaya"; };

  static std::unique_ptr<XimalayaFileLoader> Create(const X2MContentKey& key, const ScrambleTable& scramble_table);
  static std::unique_ptr<XimalayaFileLoader> Create(const X3MContentKey& key, const ScrambleTable& scramble_table);

  /**
   * @brief Create a Ximalaya X2M / X3M decryptor.
   *
   * @param key Content key, which can have a size of 4 or 32.
   * @param mul_init Initial multiplier for the scramble table generation.
   * @param mul_step Step multiplier for the scramble table generation.
   * @return std::unique_ptr<XimalayaFileLoader>
   */
  static std::unique_ptr<XimalayaFileLoader> Create(const XmlyContentKey& key, double mul_init, double mul_step);
};

}  // namespace parakeet_crypto::decryption::ximalaya
