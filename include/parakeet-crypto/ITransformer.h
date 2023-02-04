#pragma once

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto
{

enum class TransformResult
{
    OK = 0,
    ERROR_OTHER = 1,
    ERROR_INSUFFICIENT_OUTPUT = 2,
    ERROR_INVALID_FORMAT = 3,
};

class ITransformer
{
  public:
    virtual ~ITransformer() = default;

    /**
     * @brief Transform a given block of data.
     *
     * @param output Output buffer.
     * @param output_len Output size. Use `0` to get the output size.
     * @param input Input buffer.
     * @param input_len Input buffer size.
     * @return TransformResult
     */
    virtual TransformResult Transform(uint8_t *output, size_t &output_len, const uint8_t *input, size_t input_len) = 0;
};

} // namespace parakeet_crypto