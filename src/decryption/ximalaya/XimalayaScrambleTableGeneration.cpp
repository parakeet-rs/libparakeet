#include "XimalayaScrambleTableGeneration.h"

#include <algorithm>
#include <cassert>

namespace parakeet_crypto::decryption::ximalaya {

std::vector<uint16_t> generate_ximalaya_scramble_table(double mul_init, double mul_step, size_t n) {
  assert((mul_step >= 0.00 && mul_step <= 1.00, "mul_step is out of range."));
  assert((mul_init >= 3.57 && mul_init <= 4.00, "mul_init is out of range."));

  std::vector<double> vec_data(n);

  double next_value = mul_init;
  for (auto i = 0; i < n; i++) {
    vec_data[i] = next_value;
    next_value = next_value * mul_step * (1 - next_value);
  }

  // Sort it!
  std::vector<double> vec_sorted(vec_data);
  std::sort(vec_sorted.begin(), vec_sorted.end());

  // Look up its index from sorted version.
  std::vector<uint16_t> indexes(n);
  for (auto i = 0; i < n; i++) {
    auto it_found = std::find(vec_sorted.begin(), vec_sorted.end(), vec_data[i]);
    auto scrambled_index = std::distance(vec_sorted.begin(), it_found);
    indexes[i] = scrambled_index;

    // When the value duplicates, use the next index.
    // This value cannot be negative.
    vec_sorted[scrambled_index] = -1;
  }

  return indexes;
}

}  // namespace parakeet_crypto::decryption::ximalaya
