#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "ScreenDiff.h"

namespace tailgate::uwp::tests
{

TEST(Given_ScreenDiff, When_FileHasTestPrefixAndPngExtension_Then_ItMatches)
{
    const std::wstring_view fileName = L"When_StateChanges_Then_ViewMatchesGolden-dark.png";
    const std::wstring_view testName = L"When_StateChanges_Then_ViewMatchesGolden";

    const bool result = ScreenDiff::Matches(fileName, testName);

    EXPECT_TRUE(result);
}

TEST(Given_ScreenDiff, When_FileHasWrongExtension_Then_ItDoesNotMatch)
{
    const std::wstring_view fileName = L"When_StateChanges_Then_ViewMatchesGolden.jpg";
    const std::wstring_view testName = L"When_StateChanges_Then_ViewMatchesGolden";

    const bool result = ScreenDiff::Matches(fileName, testName);

    EXPECT_FALSE(result);
}

TEST(Given_ScreenDiff, When_TestNameIsEmpty_Then_ItDoesNotMatch)
{
    const std::wstring_view fileName = L"screenshot.png";
    const std::wstring_view testName;

    const bool result = ScreenDiff::Matches(fileName, testName);

    EXPECT_FALSE(result);
}

TEST(Given_ScreenDiff, When_PixelsMatch_Then_ResultIsTransparent)
{
    const ScreenDiff::Pixels reference{
        .width = 1,
        .height = 1,
        .bgra = {10, 20, 30, 255},
    };
    const ScreenDiff::Pixels actual = reference;

    const auto result = ScreenDiff::TryCreateDiff(reference, actual);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->width, 1U);
    EXPECT_EQ(result->height, 1U);
    EXPECT_EQ(result->bgra, std::vector<std::uint8_t>({0, 0, 0, 0}));
}

TEST(Given_ScreenDiff, When_PixelDiffers_Then_ResultPixelIsOpaqueMagenta)
{
    const ScreenDiff::Pixels reference{
        .width = 1,
        .height = 1,
        .bgra = {10, 20, 30, 255},
    };
    const ScreenDiff::Pixels actual{
        .width = 1,
        .height = 1,
        .bgra = {10, 21, 30, 255},
    };

    const auto result = ScreenDiff::TryCreateDiff(reference, actual);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->bgra, std::vector<std::uint8_t>({255, 0, 255, 255}));
}

TEST(Given_ScreenDiff, When_DimensionsDiffer_Then_MissingPixelsAreHighlighted)
{
    const ScreenDiff::Pixels reference{
        .width = 1,
        .height = 1,
        .bgra = {10, 20, 30, 255},
    };
    const ScreenDiff::Pixels actual{
        .width = 2,
        .height = 1,
        .bgra = {10, 20, 30, 255, 40, 50, 60, 255},
    };

    const auto result = ScreenDiff::TryCreateDiff(reference, actual);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->width, 2U);
    EXPECT_EQ(result->height, 1U);
    EXPECT_EQ(result->bgra, std::vector<std::uint8_t>({0, 0, 0, 0, 255, 0, 255, 255}));
}

TEST(Given_ScreenDiff, When_BufferSizeIsInvalid_Then_ResultIsEmpty)
{
    const ScreenDiff::Pixels reference{
        .width = 1,
        .height = 1,
        .bgra = {10, 20, 30},
    };
    const ScreenDiff::Pixels actual{
        .width = 1,
        .height = 1,
        .bgra = {10, 20, 30, 255},
    };

    const auto result = ScreenDiff::TryCreateDiff(reference, actual);

    EXPECT_FALSE(result.has_value());
}

} // namespace tailgate::uwp::tests
