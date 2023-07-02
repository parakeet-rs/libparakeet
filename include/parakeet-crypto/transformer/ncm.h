#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <cstdint>
#include <memory>

namespace parakeet_crypto::transformer
{

constexpr std::size_t kNCMContentKeySize = 128; // AES-128-ECB
constexpr std::size_t kNCMContentKeySizeBytes = 128 / 8;
std::unique_ptr<ITransformer> CreateNeteaseNCMDecryptionTransformer(const uint8_t *content_key);

} // namespace parakeet_crypto::transformer
