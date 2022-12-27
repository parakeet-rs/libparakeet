#pragma once

#include <utf8proc.h>
#include <cstdlib>
#include <string>

namespace parakeet_crypto::utils::utf8 {

std::u8string normalize(const std::u8string &str) {
  auto p_name_normalized = utf8proc_NFC(reinterpret_cast<const utf8proc_uint8_t *>(str.c_str()));
  std::u8string str_normalized = std::u8string(reinterpret_cast<char8_t *>(p_name_normalized));
  free(p_name_normalized);
  return str_normalized;
}

}
