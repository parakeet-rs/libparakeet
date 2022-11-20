#pragma once

#include <cstdint>
#include <vector>

namespace parakeet_crypto::decryption::ximalaya {

std::vector<uint16_t> generate_ximalaya_scramble_table(double mul_init, double mul_step, size_t n);

}  // namespace parakeet_crypto::decryption::ximalaya
