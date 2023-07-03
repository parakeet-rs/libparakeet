#include "gmock/gmock.h"
#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base64.h"

#include <algorithm>
#include <array>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(base64, HappyPath)
{
    std::vector<uint8_t> expected({'l', 'i', 'b', 'p', 'a', 'r', 'a', 'k', 'e', 'e', 't'});
    ASSERT_THAT(utils::Base64Decode("bGlicGFyYWtlZXQ="), ContainerEq(expected));
    ASSERT_THAT(utils::Base64Decode("bGlicGFyYWtlZXQ"), ContainerEq(expected));
}

TEST(base64, SadPath)
{
    ASSERT_THAT(utils::Base64Decode("!AA!"), ContainerEq(std::vector<uint8_t>{}));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
