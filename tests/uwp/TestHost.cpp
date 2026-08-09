#include "TestHost.h"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Graphics.Display.h>
#include <winrt/Windows.Graphics.Imaging.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.UI.ViewManagement.h>
#include <winrt/Windows.UI.Xaml.Media.Imaging.h>
#include <winrt/base.h>

#include "TestResultDisplay.h"

namespace tailgate::uwp::tests
{

namespace display = winrt::Windows::Graphics::Display;
namespace graphics_imaging = winrt::Windows::Graphics::Imaging;
namespace imaging = winrt::Windows::UI::Xaml::Media::Imaging;
namespace viewmanagement = winrt::Windows::UI::ViewManagement;

namespace
{

constexpr std::wstring_view PackagedGoldenRoot = L"ms-appx:///data/goldens/";
constexpr std::wstring_view PersistentGoldenFolder = L"goldens";
constexpr wchar_t TestThemeUri[] = L"ms-appx:///test/TestTheme.xaml";
constexpr wchar_t ScreenshotSurfaceBrushKey[] = L"TailgateTestSurfaceBrush";

struct GoldenPath final
{
    std::wstring testClass;
    std::wstring fileName;
};

struct GoldenImage final
{
    std::uint32_t width;
    std::uint32_t height;
    std::vector<std::uint8_t> pixels;
};

std::vector<std::uint8_t> ReadBuffer(const streams::IBuffer& buffer)
{
    const auto reader = streams::DataReader::FromBuffer(buffer);
    std::vector<std::uint8_t> result(buffer.Length());
    reader.ReadBytes(result);
    return result;
}

GoldenPath ParseGoldenPath(const winrt::hstring& goldenPath)
{
    const std::wstring_view path = goldenPath;
    const auto separator = path.find(L'/');
    const bool hasOneSeparator = separator != std::wstring_view::npos &&
                                 path.find(L'/', separator + 1) == std::wstring_view::npos;
    const bool hasValidComponents =
        hasOneSeparator && separator != 0 && separator + 1 < path.size();
    const bool hasPngExtension = path.ends_with(L".png");
    if (!hasValidComponents || !hasPngExtension || path.find(L'\\') != std::wstring_view::npos ||
        path.find(L"..") != std::wstring_view::npos)
    {
        throw std::invalid_argument("A golden path must have the form TestClass/FileName.png.");
    }
    return GoldenPath{
        .testClass = std::wstring(path.substr(0, separator)),
        .fileName = std::wstring(path.substr(separator + 1)),
    };
}

GoldenImage DecodePng(const streams::IRandomAccessStream& stream)
{
    stream.Seek(0);
    const auto decoder = graphics_imaging::BitmapDecoder::CreateAsync(stream).get();
    const auto pixelData =
        decoder
            .GetPixelDataAsync(graphics_imaging::BitmapPixelFormat::Bgra8,
                               graphics_imaging::BitmapAlphaMode::Premultiplied,
                               graphics_imaging::BitmapTransform(),
                               graphics_imaging::ExifOrientationMode::IgnoreExifOrientation,
                               graphics_imaging::ColorManagementMode::DoNotColorManage)
            .get();
    const auto pixels = pixelData.DetachPixelData();
    return GoldenImage{
        .width = decoder.PixelWidth(),
        .height = decoder.PixelHeight(),
        .pixels = std::vector<std::uint8_t>(pixels.begin(), pixels.end()),
    };
}

GoldenImage LoadGolden(const winrt::hstring& goldenPath)
{
    std::wstring uri(PackagedGoldenRoot);
    uri.append(goldenPath);
    const auto file =
        storage::StorageFile::GetFileFromApplicationUriAsync(foundation::Uri(uri)).get();
    const auto stream = file.OpenAsync(storage::FileAccessMode::Read).get();
    return DecodePng(stream);
}

bool PixelsMatch(const std::vector<std::uint8_t>& expected,
                 const std::vector<std::uint8_t>& actual,
                 GoldenComparisonOptions options)
{
    constexpr std::size_t BytesPerPixel = 4;
    if (expected.size() != actual.size())
    {
        return false;
    }
    std::size_t differentPixels = 0;
    for (std::size_t offset = 0; offset < expected.size(); offset += BytesPerPixel)
    {
        bool pixelDifferent = false;
        for (std::size_t channel = 0; channel < BytesPerPixel; ++channel)
        {
            const auto difference = std::abs(static_cast<int>(expected[offset + channel]) -
                                             static_cast<int>(actual[offset + channel]));
            if (difference > options.maximumChannelDifference)
            {
                return false;
            }
            pixelDifferent = pixelDifferent || difference != 0;
        }
        if (pixelDifferent && ++differentPixels > options.maximumDifferentPixels)
        {
            return false;
        }
    }
    return true;
}

storage::StorageFile CreatePersistentGolden(const GoldenPath& goldenPath)
{
    auto folder = storage::ApplicationData::Current().LocalFolder();
    folder = folder
                 .CreateFolderAsync(PersistentGoldenFolder,
                                    storage::CreationCollisionOption::OpenIfExists)
                 .get();
    folder =
        folder
            .CreateFolderAsync(goldenPath.testClass, storage::CreationCollisionOption::OpenIfExists)
            .get();
    return folder
        .CreateFileAsync(goldenPath.fileName, storage::CreationCollisionOption::ReplaceExisting)
        .get();
}

storage::StorageFile WriteActualGolden(const GoldenPath& goldenPath,
                                       const streams::IRandomAccessStream& actualPng)
{
    const auto file = CreatePersistentGolden(goldenPath);
    const auto stream = file.OpenAsync(storage::FileAccessMode::ReadWrite).get();
    actualPng.Seek(0);
    streams::RandomAccessStream::CopyAsync(actualPng, stream).get();
    stream.FlushAsync().get();
    actualPng.Seek(0);
    return file;
}

void ConfigureStandardResources(const controls::Grid& surface)
{
    xaml::ResourceDictionary testTheme;
    testTheme.Source(foundation::Uri(TestThemeUri));
    auto applicationResources = xaml::Application::Current().Resources();
    applicationResources.MergedDictionaries().Append(testTheme);
    surface.Background(applicationResources.Lookup(winrt::box_value(ScreenshotSurfaceBrushKey))
                           .as<media::Brush>());
}

} // namespace

ui_core::CoreDispatcher TestHost::s_dispatcher{nullptr};
controls::Grid TestHost::s_root{nullptr};
controls::Grid TestHost::s_surface{nullptr};
controls::TextBlock TestHost::s_status{nullptr};
ScreenshotEnvironment TestHost::s_environment{};
std::shared_ptr<TestResultDisplay> TestHost::s_resultDisplay;

void TestHost::Initialize(const ui_core::CoreDispatcher& dispatcher,
                          const controls::Grid& root,
                          const controls::Grid& surface,
                          const controls::TextBlock& status)
{
    s_dispatcher = dispatcher;
    s_root = root;
    s_surface = surface;
    s_status = status;
    s_surface.Width(StandardViewportWidth);
    s_surface.Height(StandardViewportHeight);
    s_surface.HorizontalAlignment(xaml::HorizontalAlignment::Left);
    s_surface.VerticalAlignment(xaml::VerticalAlignment::Top);
    s_surface.RequestedTheme(xaml::ElementTheme::Light);
    s_surface.Language(StandardLanguage);
    s_surface.FlowDirection(xaml::FlowDirection::LeftToRight);
    s_surface.UseLayoutRounding(true);
    ConfigureStandardResources(s_surface);

    const viewmanagement::AccessibilitySettings accessibilitySettings;
    const viewmanagement::UISettings uiSettings;
    s_environment = ScreenshotEnvironment{
        .logicalDpi = display::DisplayInformation::GetForCurrentView().LogicalDpi(),
        .textScaleFactor = uiSettings.TextScaleFactor(),
        .highContrast = accessibilitySettings.HighContrast(),
        .animationsEnabled = uiSettings.AnimationsEnabled(),
    };
}

foundation::IAsyncOperation<streams::IRandomAccessStream> TestHost::CaptureTestContentAsync()
{
    co_await winrt::resume_foreground(s_dispatcher);
    co_return co_await CaptureTestContentAsync(s_surface);
}

foundation::IAsyncOperation<streams::IRandomAccessStream>
TestHost::CaptureTestContentAsync(const xaml::UIElement& content)
{
    co_await winrt::resume_foreground(s_dispatcher);
    const imaging::RenderTargetBitmap screenshot;
    co_await screenshot.RenderAsync(content);
    const auto pixels = co_await screenshot.GetPixelsAsync();
    const streams::InMemoryRandomAccessStream stream;
    const auto encoder = co_await graphics_imaging::BitmapEncoder::CreateAsync(
        graphics_imaging::BitmapEncoder::PngEncoderId(), stream);
    encoder.SetPixelData(graphics_imaging::BitmapPixelFormat::Bgra8,
                         graphics_imaging::BitmapAlphaMode::Premultiplied,
                         static_cast<std::uint32_t>(screenshot.PixelWidth()),
                         static_cast<std::uint32_t>(screenshot.PixelHeight()),
                         StandardLogicalDpi,
                         StandardLogicalDpi,
                         ReadBuffer(pixels));
    co_await encoder.FlushAsync();
    stream.Seek(0);
    co_return stream;
}

testing::AssertionResult TestHost::CheckGolden(const xaml::UIElement& content,
                                               const winrt::hstring& goldenPath,
                                               GoldenComparisonOptions options)
{
    return CheckCapturedGolden(CaptureTestContentAsync(content).get(), goldenPath, options);
}

testing::AssertionResult TestHost::CheckGolden(const winrt::hstring& goldenPath,
                                               GoldenComparisonOptions options)
{
    return CheckCapturedGolden(CaptureTestContentAsync().get(), goldenPath, options);
}

testing::AssertionResult
TestHost::CheckCapturedGolden(const streams::IRandomAccessStream& capturedPng,
                              const winrt::hstring& goldenPath,
                              GoldenComparisonOptions options)
{
    GoldenPath parsedPath;
    try
    {
        parsedPath = ParseGoldenPath(goldenPath);
    }
    catch (const std::invalid_argument& error)
    {
        return testing::AssertionFailure() << error.what();
    }

    const auto actual = DecodePng(capturedPng);
    if (actual.width == 0 || actual.height == 0)
    {
        return testing::AssertionFailure()
               << "Golden content must render with positive dimensions.";
    }

    try
    {
        const auto expected = LoadGolden(goldenPath);
        if (expected.width == actual.width && expected.height == actual.height)
        {
            if (expected.pixels == actual.pixels)
            {
                return testing::AssertionSuccess();
            }
            if (PixelsMatch(expected.pixels, actual.pixels, options))
            {
                (void)WriteActualGolden(parsedPath, capturedPng);
                return testing::AssertionSuccess();
            }
        }
    }
    catch (const winrt::hresult_error&)
    {
    }

    try
    {
        const auto actualFile = WriteActualGolden(parsedPath, capturedPng);
        return testing::AssertionFailure()
               << "Golden is missing or does not match: data/goldens/"
               << winrt::to_string(goldenPath)
               << ". Captured PNG: " << winrt::to_string(actualFile.Path());
    }
    catch (const winrt::hresult_error& error)
    {
        return testing::AssertionFailure()
               << "Golden is missing or does not match: data/goldens/"
               << winrt::to_string(goldenPath)
               << ". Could not write captured PNG: " << winrt::to_string(error.message());
    }
}

ScreenshotEnvironment TestHost::Environment() noexcept
{
    return s_environment;
}

foundation::IAsyncAction TestHost::CompleteTestRunAsync(const winrt::hstring& message,
                                                        TestRunResult result)
{
    co_await winrt::resume_foreground(s_dispatcher);
    s_status.Text(message);
    s_resultDisplay =
        std::make_shared<TestResultDisplay>(s_root, message, OutputFileName, std::move(result));
    co_await s_resultDisplay->ShowAsync();
}

} // namespace tailgate::uwp::tests
