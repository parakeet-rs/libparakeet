#include "parakeet-crypto/decryption/tencent/EKeyProvider.h"
#include "utils/utf8.hpp"

namespace parakeet_crypto::decryption::tencent {

void EKeyProvider::AddKey(const std::u8string& name, const std::string& ekey) {
  auto name_normalized = utils::utf8::normalize(name);
  ekey_store_[name_normalized] = ekey;
}

std::string EKeyProvider::FindKey(const std::u8string& name) const {
  auto name_normalized = utils::utf8::normalize(name);

  auto it = ekey_store_.find(name_normalized);
  return it == ekey_store_.end() ? std::string{""} : it->second;
}

}  // namespace parakeet_crypto::decryption::tencent