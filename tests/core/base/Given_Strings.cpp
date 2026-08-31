#include <string_view>

#include <gtest/gtest.h>

#include <tailgate/base/Strings.h>

TEST(Given_Strings, When_StringWithTrailingWhitespaceAndTrimmingEnd_Then_RemovesWhitespace)
{
    constexpr std::string_view value = "response body \t\r\n";

    const std::string_view result = tailgate::base::TrimEnd(value);

    EXPECT_EQ(result, "response body");
}

TEST(Given_Strings, When_StringWithLeadingWhitespaceAndTrimmingEnd_Then_PreservesLeadingWhitespace)
{
    constexpr std::string_view value = "\t response body";

    const std::string_view result = tailgate::base::TrimEnd(value);

    EXPECT_EQ(result, value);
}

TEST(Given_Strings, When_StringWithoutTrailingWhitespaceAndTrimmingEnd_Then_PreservesString)
{
    constexpr std::string_view value = "response body";

    const std::string_view result = tailgate::base::TrimEnd(value);

    EXPECT_EQ(result, value);
}

TEST(Given_Strings, When_WhitespaceOnlyStringAndTrimmingEnd_Then_ReturnsEmptyString)
{
    constexpr std::string_view value = " \t\r\n\f\v";

    const std::string_view result = tailgate::base::TrimEnd(value);

    EXPECT_TRUE(result.empty());
}
