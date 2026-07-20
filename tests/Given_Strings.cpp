#include <string_view>

#include <gtest/gtest.h>

#include <tailgate/Strings.h>

TEST(Given_StringWithTrailingWhitespace, When_TrimmingEnd_Then_RemovesWhitespace)
{
    constexpr std::string_view value = "response body \t\r\n";

    const std::string_view result = tailgate::TrimEnd(value);

    EXPECT_EQ(result, "response body");
}

TEST(Given_StringWithLeadingWhitespace, When_TrimmingEnd_Then_PreservesLeadingWhitespace)
{
    constexpr std::string_view value = "\t response body";

    const std::string_view result = tailgate::TrimEnd(value);

    EXPECT_EQ(result, value);
}

TEST(Given_StringWithoutTrailingWhitespace, When_TrimmingEnd_Then_PreservesString)
{
    constexpr std::string_view value = "response body";

    const std::string_view result = tailgate::TrimEnd(value);

    EXPECT_EQ(result, value);
}

TEST(Given_WhitespaceOnlyString, When_TrimmingEnd_Then_ReturnsEmptyString)
{
    constexpr std::string_view value = " \t\r\n\f\v";

    const std::string_view result = tailgate::TrimEnd(value);

    EXPECT_TRUE(result.empty());
}
