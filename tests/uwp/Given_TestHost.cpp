#include <cstddef>
#include <cstdint>

#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Graphics.Imaging.h>
#include <winrt/Windows.UI.Xaml.Controls.h>
#include <winrt/Windows.UI.Xaml.Media.h>
#include <winrt/Windows.UI.h>

#include <gtest/gtest.h>

#include "TestHost.h"

namespace tailgate::uwp::tests
{

namespace appmodel = winrt::Windows::ApplicationModel;
namespace graphics_imaging = winrt::Windows::Graphics::Imaging;

TEST(Given_TestHost, When_PackageRuns_Then_IdentityIsAvailable)
{
    const auto package = appmodel::Package::Current();

    const auto packageName = package.Id().Name();

    EXPECT_EQ(L"Tailgate.Tests", packageName);
}

TEST(Given_TestHost, When_XamlElementIsAttached_Then_GoldenCanBeCaptured)
{
    constexpr double Width = 180;
    constexpr double Height = 64;
    constexpr double BorderWidth = 2;
    constexpr double Padding = 12;
    const auto content = TestHost::SetTestContentAsync(
                             []() -> xaml::UIElement
                             {
                                 xaml::Thickness borderThickness;
                                 borderThickness.Left = BorderWidth;
                                 borderThickness.Top = BorderWidth;
                                 borderThickness.Right = BorderWidth;
                                 borderThickness.Bottom = BorderWidth;
                                 xaml::Thickness padding;
                                 padding.Left = Padding;
                                 padding.Top = Padding;
                                 padding.Right = Padding;
                                 padding.Bottom = Padding;
                                 const controls::TextBlock text;
                                 text.Text(L"Hello World!");
                                 text.Foreground(media::SolidColorBrush(ui::Colors::Blue()));
                                 text.HorizontalAlignment(xaml::HorizontalAlignment::Center);
                                 text.VerticalAlignment(xaml::VerticalAlignment::Center);
                                 const controls::Border result;
                                 result.Width(Width);
                                 result.Height(Height);
                                 result.Background(media::SolidColorBrush(ui::Colors::White()));
                                 result.BorderBrush(media::SolidColorBrush(ui::Colors::Black()));
                                 result.BorderThickness(borderThickness);
                                 result.Padding(padding);
                                 result.Child(text);
                                 return result;
                             })
                             .get();

    const auto result = TestHost::CheckGolden(
        content, L"Given_TestHost/When_XamlElementIsAttached_Then_GoldenCanBeCaptured.png");

    EXPECT_TRUE(result);
}

TEST(Given_TestHost, When_ContentIsCaptured_Then_FocusMovesOutsideContent)
{
    controls::TextBox content{nullptr};
    bool receivedFocus = false;
    TestHost::SetTestContentAsync(
        [&content]() -> xaml::UIElement
        {
            content = controls::TextBox();
            return content;
        })
        .get();
    TestHost::RunOnUiThread(
        [&content, &receivedFocus]
        {
            receivedFocus = content.Focus(xaml::FocusState::Programmatic);
        });
    ASSERT_TRUE(receivedFocus);

    (void)TestHost::CaptureTestContentAsync(content).get();
    xaml::FocusState focusState = xaml::FocusState::Programmatic;
    TestHost::RunOnUiThread(
        [&content, &focusState]
        {
            focusState = content.FocusState();
        });

    EXPECT_EQ(xaml::FocusState::Unfocused, focusState);
}

TEST(Given_TestHost, When_ContentDimensionsChangeAcrossFrames_Then_FinalDimensionsAreCaptured)
{
    constexpr double InitialWidth = 100.0;
    constexpr double IntermediateWidth = 140.0;
    constexpr double FinalWidth = 180.0;
    constexpr double Height = 64.0;
    constexpr std::uint32_t ExpectedWidth = 180;
    constexpr std::uint32_t ExpectedHeight = 64;
    const auto content = TestHost::SetTestContentAsync(
                             [initialWidth = InitialWidth, height = Height]() -> xaml::UIElement
                             {
                                 const controls::Border result;
                                 result.Width(initialWidth);
                                 result.Height(height);
                                 return result;
                             })
                             .get()
                             .as<controls::Border>();
    std::size_t renderingCount = 0;
    winrt::event_token renderingToken;
    TestHost::RunOnUiThread(
        [content,
         &renderingCount,
         &renderingToken,
         intermediateWidth = IntermediateWidth,
         finalWidth = FinalWidth]
        {
            renderingToken = media::CompositionTarget::Rendering(
                [content, &renderingCount, &renderingToken, intermediateWidth, finalWidth](
                    const foundation::IInspectable&, const foundation::IInspectable&)
                {
                    ++renderingCount;
                    if (renderingCount == 1)
                    {
                        content.Width(intermediateWidth);
                    }
                    else if (renderingCount == 2)
                    {
                        content.Width(finalWidth);
                        media::CompositionTarget::Rendering(renderingToken);
                    }
                });
        });

    const auto screenshot = TestHost::CaptureTestContentAsync(content).get();
    const auto decoder = graphics_imaging::BitmapDecoder::CreateAsync(screenshot).get();

    EXPECT_EQ(ExpectedWidth, decoder.PixelWidth());
    EXPECT_EQ(ExpectedHeight, decoder.PixelHeight());
}

} // namespace tailgate::uwp::tests
