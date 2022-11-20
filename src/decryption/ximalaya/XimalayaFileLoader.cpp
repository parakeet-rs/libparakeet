#include "XimalayaScrambleTableGeneration.h"

#include "internal/XorHelper.h"
#include "parakeet-crypto/decryption/ximalaya/XimalayaFileLoader.h"
#include "parakeet-crypto/utils/StringHelper.h"

#include <array>
#include <cassert>

namespace parakeet_crypto::decryption::ximalaya {

namespace detail {

enum class State {
  kDecryptHeader = 0,
  kPassThrough,
};

template <std::size_t ContentKeySize>
class XimalayaFileLoaderImpl : public XimalayaFileLoader {
 private:
  std::string name_;
  std::array<uint8_t, ContentKeySize> content_key_;
  ScrambleTable scramble_table_;
  State state_ = State::kDecryptHeader;

 public:
  XimalayaFileLoaderImpl(const std::array<uint8_t, ContentKeySize>& content_key,
                         const ScrambleTable& scramble_table,
                         const char* subtype)
      : content_key_(content_key), scramble_table_(scramble_table) {
    name_ = utils::Format("Ximalaya(%s)", subtype);
  }

  virtual const std::string GetName() const override { return name_; };

  void DoHeaderDecryption() {
    auto p_out = ExpandOutputBuffer(kScrambleTableSize);

    for (std::size_t i = 0; i < kScrambleTableSize; i++) {
      std::size_t idx = scramble_table_[i];
      p_out[i] = buf_in_[idx] ^ content_key_[i % ContentKeySize];
    }
  }

  bool Write(const uint8_t* in, std::size_t len) override {
    while (len) {
      switch (state_) {
        case State::kDecryptHeader:
          if (ReadUntilOffset(in, len, kScrambleTableSize)) {
            DoHeaderDecryption();
            state_ = State::kPassThrough;
          }
          break;

        case State::kPassThrough:
          buf_out_.insert(buf_out_.end(), in, in + len);
          return true;
      }
    }

    return len == 0;
  };

  bool End() override { return !InErrorState(); }
};

X3MContentKey FromShorterContentKey(const std::span<const uint8_t>& key) {
  X3MContentKey new_key;
  assert(((kX3MContentKeySize % key.size()) == 0, "key.size() size should be a factor of kX3MContentKeySize"));
  assert((kX3MContentKeySize >= key.size(), "key.size() size should not be greater than kX3MContentKeySize"));

  for (std::size_t i = 0; i < kX3MContentKeySize; i += key.size()) {
    std::copy(key.begin(), key.end(), &new_key[i]);
  }

  return new_key;
}

}  // namespace detail

std::unique_ptr<XimalayaFileLoader> XimalayaFileLoader::Create(const X2MContentKey& key,
                                                               const ScrambleTable& scramble_table) {
  return std::make_unique<detail::XimalayaFileLoaderImpl<kX3MContentKeySize>>(
      detail::FromShorterContentKey(std::span{key}), scramble_table, "X2M");
}

std::unique_ptr<XimalayaFileLoader> XimalayaFileLoader::Create(const X3MContentKey& key,
                                                               const ScrambleTable& scramble_table) {
  return std::make_unique<detail::XimalayaFileLoaderImpl<kX3MContentKeySize>>(key, scramble_table, "X3M");
}

std::unique_ptr<XimalayaFileLoader> XimalayaFileLoader::Create(const XmlyContentKey& key,
                                                               double mul_init,
                                                               double mul_step) {
  auto scramble_table_vec = generate_ximalaya_scramble_table(mul_init, mul_step, kScrambleTableSize);
  ScrambleTable scramble_table;
  std::copy(scramble_table_vec.begin(), scramble_table_vec.end(), scramble_table.begin());

  if (key.size() == kX2MContentKeySize || key.size() == kX3MContentKeySize) {
    return Create(detail::FromShorterContentKey(std::span{key}), scramble_table);
  }

  return nullptr;
}

}  // namespace parakeet_crypto::decryption::ximalaya
