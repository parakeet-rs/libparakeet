#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "md5.h"

#include <algorithm>
#include <array>
#include <cstdint>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(MD5, QuickTest)
{
    std::array<uint8_t, 16> expected = {0x21, 0xAE, 0xC4, 0xD2, 0x42, 0x57, 0x38, 0xBB,
                                        0x53, 0x30, 0x70, 0xE7, 0x42, 0x6F, 0xE3, 0x09};

    auto actual = utils::md5_str("libparakeet");

    ASSERT_THAT(actual, ContainerEq(expected));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
