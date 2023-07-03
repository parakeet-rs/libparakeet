#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace parakeet_crypto::utils
{

std::string Hex(const uint8_t *data, size_t len, bool upper = true);

} // namespace parakeet_crypto::utils
