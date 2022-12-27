#pragma once

#include <map>
#include <string>

namespace parakeet_crypto::decryption::tencent {

class EKeyProvider {
 public:
  void AddKey(const std::u8string& name, const std::string& ekey);
  void Clear() { ekey_store_.clear(); }

  [[nodiscard]] std::string FindKey(const std::u8string& name) const;
  [[nodiscard]] std::map<std::u8string, std::string> GetEKeys() const { return ekey_store_; }

 private:
  std::map<std::u8string, std::string> ekey_store_;
};

}  // namespace parakeet_crypto::decryption::tencent
