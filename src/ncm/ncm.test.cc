#include "parakeet-crypto/transformer/ncm.h"
#include "parakeet-crypto/IStream.h"
#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/transformer/qmc.h"
#include "test/read_fixture.test.hh"
#include "test/test_decryption.test.hh"

#include <cstdio>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(NCM, TestDecryption)
{
    static constexpr std::array<const uint8_t, 16> ncm_key = {0x80, 0x88, 0x6A, 0x09, 0x09, 0x2E, 0x28, 0x7F,
                                                              0xB1, 0x66, 0xB3, 0x8D, 0x0C, 0xEB, 0xC7, 0x1A};

    auto transformer = transformer::CreateNeteaseNCMDecryptionTransformer(ncm_key.data());
    test::should_decrypt_to_fixture("test.ncm", transformer);
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
