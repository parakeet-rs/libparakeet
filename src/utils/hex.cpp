#include "utils/hex.h"

#include <cstddef>
#include <string>

constexpr static const char *kHexUpper = "0123456789ABCDEF";
constexpr static const char *kHexLower = "0123456789abcdef";

namespace parakeet_crypto::utils
{

std::string Hex(const uint8_t *data, size_t len, bool upper)
{
    constexpr size_t kShiftUpperHalfByte = 4;
    constexpr size_t kMaskLowerHalfByte = 0x0F;

    const char *hex_table = upper ? kHexUpper : kHexLower;
    std::string result(len * 2, 0);

    size_t write_offset = 0;
    for (size_t i = 0; i < len; i++)
    {
        auto value = data[i];
        result[write_offset++] = hex_table[value >> kShiftUpperHalfByte];
        result[write_offset++] = hex_table[value & kMaskLowerHalfByte];
    }

    return result;
}

} // namespace parakeet_crypto::utils
