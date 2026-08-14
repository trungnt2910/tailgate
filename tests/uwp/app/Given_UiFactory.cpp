#include <memory>

#include <gtest/gtest.h>

#include "app/ui/AppResources.h"
#include "app/ui/UiFactory.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{

TEST(Given_UiFactory, When_BuildingMargin_Then_SidesRetainTheirMeaning)
{
    constexpr double Left = 1;
    constexpr double Top = 2;
    constexpr double Right = 3;
    constexpr double Bottom = 4;

    const xaml::Thickness result = UiFactory::Margin(Left, Top, Right, Bottom);

    EXPECT_DOUBLE_EQ(result.Left, Left);
    EXPECT_DOUBLE_EQ(result.Top, Top);
    EXPECT_DOUBLE_EQ(result.Right, Right);
    EXPECT_DOUBLE_EQ(result.Bottom, Bottom);
}

TEST(Given_UiFactory, When_BuildingTextAndRows_Then_ContentAndOptionalIconArePreserved)
{
    winrt::hstring textValue;
    std::uint32_t textOnlyChildren = 0;
    std::uint32_t iconRowChildren = 0;

    TestHost::RunOnUiThread(
        [&textValue, &textOnlyChildren, &iconRowChildren]
        {
            AppResources resources;
            const UiFactory subject(resources);
            const auto text = subject.Text(L"Hello", AppStyle::TextBody);
            const auto textOnly = subject.ValueWithIconRow(L"Primary", L"", nullptr);
            const auto withIcon = subject.ValueWithIconRow(L"Primary", L"Secondary", L"\xE8B7");
            textValue = text.Text();
            textOnlyChildren = textOnly.Children().Size();
            iconRowChildren = withIcon.Children().Size();
        });

    EXPECT_EQ(textValue, L"Hello");
    EXPECT_EQ(textOnlyChildren, 1U);
    EXPECT_EQ(iconRowChildren, 2U);
}

TEST(Given_UiFactory, When_BuildingFallbackProfilePicture_Then_SizedCircleAndIconArePresent)
{
    constexpr double PictureSize = 48.0;
    double width = 0.0;
    double height = 0.0;
    std::uint32_t children = 0;

    TestHost::RunOnUiThread(
        [&width, &height, &children]
        {
            AppResources resources;
            const UiFactory subject(resources);
            const auto picture = subject.ProfilePicture(PictureSize, nullptr).as<controls::Grid>();
            width = picture.Width();
            height = picture.Height();
            children = picture.Children().Size();
        });

    EXPECT_DOUBLE_EQ(width, PictureSize);
    EXPECT_DOUBLE_EQ(height, PictureSize);
    EXPECT_EQ(children, 2U);
}

TEST(Given_UiFactory, When_BuildingPageChrome_Then_ContentOccupiesStarRow)
{
    std::uint32_t rows = 0;
    std::uint32_t children = 0;
    std::int32_t contentRow = -1;

    TestHost::RunOnUiThread(
        [&rows, &children, &contentRow]
        {
            AppResources resources;
            const UiFactory subject(resources);
            const controls::Grid content;
            const auto page = subject.PageChrome(L"Title", content);
            rows = page.RowDefinitions().Size();
            children = page.Children().Size();
            contentRow = controls::Grid::GetRow(content);
        });

    EXPECT_EQ(rows, 2U);
    EXPECT_EQ(children, 2U);
    EXPECT_EQ(contentRow, 1);
}

} // namespace tailgate::uwp::tests
