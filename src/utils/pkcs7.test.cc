#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "pkcs7.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(PKCS7, QuickTest_HappyPath)
{
    ASSERT_EQ(utils::PKCS7_unpad(std::array<uint8_t, 5>{0xFF, 0x04, 0x04, 0x04, 0x04}), 1);
    ASSERT_EQ(utils::PKCS7_unpad(std::array<uint8_t, 6>{0xFF, 0x04, 0x04, 0x04, 0x04, 0x04}), 2);
}

TEST(PKCS7, QuickTest_SadPath)
{
    ASSERT_EQ(utils::PKCS7_unpad(std::array<uint8_t, 0>{}), 0);
    ASSERT_EQ(utils::PKCS7_unpad(std::array<uint8_t, 5>{0xFF, 0x04, 0x04, 0x04, 0x05}), -1);
    ASSERT_EQ(utils::PKCS7_unpad(std::array<uint8_t, 5>{0xFF, 0x04, 0x04, 0x04, 0x00}), -1);
    ASSERT_EQ(utils::PKCS7_unpad(std::array<uint8_t, 5>{0xFF, 0x01, 0x02, 0x03, 0x04}), -2);
    ASSERT_EQ(utils::PKCS7_unpad<3>(std::array<uint8_t, 5>{0xFF, 0x04, 0x04, 0x04, 0x04}), -3);
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
