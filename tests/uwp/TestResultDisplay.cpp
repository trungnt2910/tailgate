#include "TestResultDisplay.h"

#include <algorithm>
#include <cstdint>
#include <format>
#include <string>
#include <utility>
#include <vector>

#include <winrt/Windows.Graphics.Imaging.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.System.h>
#include <winrt/Windows.UI.Core.h>
#include <winrt/Windows.UI.Xaml.Input.h>
#include <winrt/Windows.UI.Xaml.Media.Imaging.h>
#include <winrt/base.h>

#include "ScreenDiff.h"

namespace tailgate::uwp::tests
{

namespace graphics_imaging = winrt::Windows::Graphics::Imaging;
namespace imaging = winrt::Windows::UI::Xaml::Media::Imaging;
namespace streams = winrt::Windows::Storage::Streams;
namespace system = winrt::Windows::System;

namespace
{

constexpr wchar_t PersistentGoldenFolder[] = L"goldens";
constexpr std::wstring_view PackagedGoldenRoot = L"ms-appx:///data/goldens/";
constexpr wchar_t OpenLogsLabel[] = L"Open logs";
constexpr wchar_t FailedTestsLabel[] = L"Failed tests";
constexpr wchar_t NoFailedTestsLabel[] = L"No failed tests.";
constexpr wchar_t ScreenshotsAvailableLabel[] = L" (screenshots available)";
constexpr wchar_t BackLabel[] = L"Back";
constexpr wchar_t ReferenceLabel[] = L"Reference";
constexpr wchar_t DifferenceLabel[] = L"Difference";
constexpr wchar_t ActualLabel[] = L"Actual";
constexpr wchar_t DifferenceUnavailableLabel[] = L"Difference unavailable";
constexpr double PageMargin = 24.0;
constexpr double ElementSpacing = 12.0;
constexpr double ScreenshotMaxHeight = 480.0;
constexpr double EqualColumnWidth = 1.0;
constexpr float StandardLogicalDpi = 96.0F;
constexpr std::size_t ComparisonColumnCount = 3;

enum class ComparisonColumn : std::int32_t
{
    Reference,
    Center,
    Difference = Center,
    Actual,
};

enum class ComparisonRow : std::int32_t
{
    Label,
    Image,
};

[[nodiscard]] xaml::Thickness UniformThickness(double value) noexcept
{
    xaml::Thickness thickness;
    thickness.Left = value;
    thickness.Top = value;
    thickness.Right = value;
    thickness.Bottom = value;
    return thickness;
}

[[nodiscard]] xaml::Thickness BottomThickness(double value) noexcept
{
    xaml::Thickness thickness;
    thickness.Bottom = value;
    return thickness;
}

[[nodiscard]] std::vector<std::uint8_t> ReadBuffer(const streams::IBuffer& buffer)
{
    const auto reader = streams::DataReader::FromBuffer(buffer);
    std::vector<std::uint8_t> result(buffer.Length());
    reader.ReadBytes(result);
    return result;
}

[[nodiscard]] foundation::IAsyncAction DecodePngAsync(const storage::StorageFile& file,
                                                      ScreenDiff::Pixels& result)
{
    const auto stream = co_await file.OpenAsync(storage::FileAccessMode::Read);
    const auto decoder = co_await graphics_imaging::BitmapDecoder::CreateAsync(stream);
    const auto pixelData = co_await decoder.GetPixelDataAsync(
        graphics_imaging::BitmapPixelFormat::Bgra8,
        graphics_imaging::BitmapAlphaMode::Premultiplied,
        graphics_imaging::BitmapTransform(),
        graphics_imaging::ExifOrientationMode::IgnoreExifOrientation,
        graphics_imaging::ColorManagementMode::DoNotColorManage);
    const auto pixels = pixelData.DetachPixelData();
    result = ScreenDiff::Pixels{
        .width = decoder.PixelWidth(),
        .height = decoder.PixelHeight(),
        .bgra = std::vector<std::uint8_t>(pixels.begin(), pixels.end()),
    };
}

[[nodiscard]] foundation::IAsyncOperation<media::ImageSource>
LoadImageAsync(const storage::StorageFile& file)
{
    const auto stream = co_await file.OpenAsync(storage::FileAccessMode::Read);
    imaging::BitmapImage image;
    co_await image.SetSourceAsync(stream);
    co_return image;
}

[[nodiscard]] foundation::IAsyncOperation<streams::IRandomAccessStream>
EncodeDifferenceAsync(const ScreenDiff::Pixels& pixels)
{
    const streams::InMemoryRandomAccessStream stream;
    const auto encoder = co_await graphics_imaging::BitmapEncoder::CreateAsync(
        graphics_imaging::BitmapEncoder::PngEncoderId(), stream);
    encoder.SetPixelData(graphics_imaging::BitmapPixelFormat::Bgra8,
                         graphics_imaging::BitmapAlphaMode::Premultiplied,
                         pixels.width,
                         pixels.height,
                         StandardLogicalDpi,
                         StandardLogicalDpi,
                         pixels.bgra);
    co_await encoder.FlushAsync();
    stream.Seek(0);
    co_return stream;
}

[[nodiscard]] foundation::IAsyncOperation<storage::StorageFile>
LoadReferenceAsync(const FailedTestResult& test, const winrt::hstring& fileName)
{
    const std::wstring uri =
        std::format(L"{}{}/{}", PackagedGoldenRoot, test.testSuite, std::wstring_view(fileName));
    try
    {
        co_return co_await storage::StorageFile::GetFileFromApplicationUriAsync(
            foundation::Uri(uri));
    }
    catch (const winrt::hresult_error&)
    {
        co_return nullptr;
    }
}

[[nodiscard]] controls::TextBlock Text(std::wstring_view value)
{
    controls::TextBlock text;
    text.Text(winrt::hstring(value));
    text.TextWrapping(xaml::TextWrapping::Wrap);
    return text;
}

[[nodiscard]] xaml::FrameworkElement ImageCell(const media::ImageSource& source,
                                               std::wstring_view unavailableText)
{
    if (!source)
    {
        auto text = Text(unavailableText);
        text.HorizontalAlignment(xaml::HorizontalAlignment::Center);
        text.VerticalAlignment(xaml::VerticalAlignment::Center);
        return text;
    }
    controls::Image image;
    image.Source(source);
    image.MaxHeight(ScreenshotMaxHeight);
    image.Stretch(media::Stretch::Uniform);
    image.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    image.VerticalAlignment(xaml::VerticalAlignment::Top);
    return image;
}

void AddEqualColumns(const controls::Grid& grid)
{
    for (std::size_t index = 0; index < ComparisonColumnCount; ++index)
    {
        controls::ColumnDefinition column;
        column.Width(
            xaml::GridLengthHelper::FromValueAndType(EqualColumnWidth, xaml::GridUnitType::Star));
        grid.ColumnDefinitions().Append(column);
    }
}

void AddComparisonCell(const controls::Grid& grid,
                       const xaml::FrameworkElement& cell,
                       ComparisonColumn column,
                       ComparisonRow row)
{
    controls::Grid::SetColumn(cell, static_cast<std::int32_t>(column));
    controls::Grid::SetRow(cell, static_cast<std::int32_t>(row));
    grid.Children().Append(cell);
}

[[nodiscard]] controls::Grid CreateComparisonGrid()
{
    controls::Grid comparison;
    comparison.Margin(BottomThickness(ElementSpacing));
    AddEqualColumns(comparison);
    controls::RowDefinition labels;
    labels.Height(xaml::GridLengthHelper::Auto());
    comparison.RowDefinitions().Append(labels);
    controls::RowDefinition images;
    images.Height(xaml::GridLengthHelper::Auto());
    comparison.RowDefinitions().Append(images);
    return comparison;
}

[[nodiscard]] foundation::IAsyncOperation<controls::Grid>
CreateComparisonAsync(const FailedTestResult& test, const storage::StorageFile& actualFile)
{
    const auto actualImage = co_await LoadImageAsync(actualFile);
    const auto referenceFile = co_await LoadReferenceAsync(test, actualFile.Name());
    if (!referenceFile)
    {
        auto comparison = CreateComparisonGrid();
        AddComparisonCell(
            comparison, Text(ActualLabel), ComparisonColumn::Center, ComparisonRow::Label);
        AddComparisonCell(comparison,
                          ImageCell(actualImage, L""),
                          ComparisonColumn::Center,
                          ComparisonRow::Image);
        co_return comparison;
    }

    const auto dispatcher = xaml::Window::Current().Dispatcher();
    co_await winrt::resume_background();
    ScreenDiff::Pixels actualPixels;
    co_await DecodePngAsync(actualFile, actualPixels);
    ScreenDiff::Pixels referencePixels;
    co_await DecodePngAsync(referenceFile, referencePixels);
    const auto referenceImage = co_await LoadImageAsync(referenceFile);
    const auto difference = ScreenDiff::TryCreateDiff(referencePixels, actualPixels);
    media::ImageSource differenceImage{nullptr};
    streams::IRandomAccessStream differenceStream{nullptr};
    if (difference.has_value() && difference->width != 0 && difference->height != 0)
    {
        differenceStream = co_await EncodeDifferenceAsync(*difference);
    }
    co_await winrt::resume_foreground(dispatcher);
    if (differenceStream)
    {
        imaging::BitmapImage image;
        co_await image.SetSourceAsync(differenceStream);
        differenceImage = image;
    }

    auto comparison = CreateComparisonGrid();

    AddComparisonCell(
        comparison, Text(ReferenceLabel), ComparisonColumn::Reference, ComparisonRow::Label);
    AddComparisonCell(
        comparison, Text(DifferenceLabel), ComparisonColumn::Difference, ComparisonRow::Label);
    AddComparisonCell(
        comparison, Text(ActualLabel), ComparisonColumn::Actual, ComparisonRow::Label);
    AddComparisonCell(comparison,
                      ImageCell(referenceImage, L""),
                      ComparisonColumn::Reference,
                      ComparisonRow::Image);
    AddComparisonCell(comparison,
                      ImageCell(differenceImage, DifferenceUnavailableLabel),
                      ComparisonColumn::Difference,
                      ComparisonRow::Image);
    AddComparisonCell(
        comparison, ImageCell(actualImage, L""), ComparisonColumn::Actual, ComparisonRow::Image);
    co_return comparison;
}

} // namespace

TestResultDisplay::TestResultDisplay(const controls::Grid& root,
                                     winrt::hstring message,
                                     winrt::hstring outputFileName,
                                     TestRunResult result)
    : m_root(root),
      m_message(std::move(message)),
      m_outputFileName(std::move(outputFileName)),
      m_result(std::move(result))
{
}

foundation::IAsyncAction TestResultDisplay::ShowAsync()
{
    m_failures.clear();
    const auto localFolder = storage::ApplicationData::Current().LocalFolder();
    const auto goldenItem = co_await localFolder.TryGetItemAsync(PersistentGoldenFolder);
    const auto goldenFolder = goldenItem.try_as<storage::StorageFolder>();
    for (const auto& failedTest : m_result.failedTests)
    {
        DisplayedFailure displayed{
            .test = failedTest,
            .screenshots = {},
        };
        if (goldenFolder)
        {
            const auto suiteItem = co_await goldenFolder.TryGetItemAsync(failedTest.testSuite);
            const auto suiteFolder = suiteItem.try_as<storage::StorageFolder>();
            if (suiteFolder)
            {
                const auto files = co_await suiteFolder.GetFilesAsync();
                for (const auto& file : files)
                {
                    if (ScreenDiff::Matches(file.Name(), failedTest.testName))
                    {
                        displayed.screenshots.push_back(file);
                    }
                }
                std::ranges::sort(
                    displayed.screenshots,
                    [](const storage::StorageFile& left, const storage::StorageFile& right)
                    {
                        return left.Name() < right.Name();
                    });
            }
        }
        m_failures.push_back(std::move(displayed));
    }
    ShowSummary();
}

controls::Grid TestResultDisplay::CreateSummaryPage()
{
    controls::Grid page;
    page.Margin(UniformThickness(PageMargin));
    controls::RowDefinition headerRow;
    headerRow.Height(xaml::GridLengthHelper::Auto());
    page.RowDefinitions().Append(headerRow);
    controls::RowDefinition failuresRow;
    failuresRow.Height(
        xaml::GridLengthHelper::FromValueAndType(EqualColumnWidth, xaml::GridUnitType::Star));
    page.RowDefinitions().Append(failuresRow);

    controls::StackPanel header;
    header.Spacing(ElementSpacing);
    header.Margin(BottomThickness(ElementSpacing));
    header.Children().Append(Text(m_message));
    controls::Button logs;
    logs.Content(winrt::box_value(OpenLogsLabel));
    logs.Click(
        [this](const auto&, const auto&)
        {
            OpenLogsAsync();
        });
    header.Children().Append(logs);
    page.Children().Append(header);

    controls::StackPanel failures;
    failures.Children().Append(Text(FailedTestsLabel));
    if (m_failures.empty())
    {
        auto noFailures = Text(NoFailedTestsLabel);
        noFailures.Margin(BottomThickness(ElementSpacing));
        failures.Children().Append(noFailures);
    }
    else
    {
        controls::ListView list;
        for (std::size_t index = 0; index < m_failures.size(); ++index)
        {
            const auto& failure = m_failures[index];
            const std::wstring fullName = std::format(
                L"{}.{}{}",
                failure.test.testSuite,
                failure.test.testName,
                failure.screenshots.empty() ? std::wstring_view() : ScreenshotsAvailableLabel);
            controls::ListViewItem item;
            item.Content(winrt::box_value(fullName));
            if (!failure.screenshots.empty())
            {
                item.Tapped(
                    [this, index](const auto&, const auto&)
                    {
                        ShowScreenshotsAsync(index);
                    });
            }
            list.Items().Append(item);
        }
        failures.Children().Append(list);
    }
    controls::Grid::SetRow(failures, 1);
    page.Children().Append(failures);
    return page;
}

FireAndForget TestResultDisplay::OpenLogsAsync()
{
    const auto folder = storage::ApplicationData::Current().TemporaryFolder();
    const auto file = co_await folder.GetFileAsync(m_outputFileName);
    (void)co_await system::Launcher::LaunchFileAsync(file);
}

void TestResultDisplay::ShowSummary()
{
    m_root.Children().Clear();
    m_root.Children().Append(CreateSummaryPage());
}

FireAndForget TestResultDisplay::ShowScreenshotsAsync(std::size_t failureIndex)
{
    if (failureIndex >= m_failures.size() || m_failures[failureIndex].screenshots.empty())
    {
        co_return;
    }
    const auto& failure = m_failures[failureIndex];
    controls::Grid page;
    page.Margin(UniformThickness(PageMargin));
    controls::RowDefinition headerRow;
    headerRow.Height(xaml::GridLengthHelper::Auto());
    page.RowDefinitions().Append(headerRow);
    controls::RowDefinition contentRow;
    contentRow.Height(
        xaml::GridLengthHelper::FromValueAndType(EqualColumnWidth, xaml::GridUnitType::Star));
    page.RowDefinitions().Append(contentRow);

    controls::StackPanel header;
    header.Orientation(controls::Orientation::Horizontal);
    header.Spacing(ElementSpacing);
    header.Margin(BottomThickness(ElementSpacing));
    controls::Button back;
    back.Content(winrt::box_value(BackLabel));
    back.Click(
        [this](const auto&, const auto&)
        {
            ShowSummary();
        });
    header.Children().Append(back);
    header.Children().Append(
        Text(std::format(L"{}.{}", failure.test.testSuite, failure.test.testName)));
    page.Children().Append(header);

    controls::StackPanel comparisons;
    comparisons.Spacing(ElementSpacing);
    for (const auto& screenshot : failure.screenshots)
    {
        comparisons.Children().Append(Text(screenshot.Name()));
        comparisons.Children().Append(co_await CreateComparisonAsync(failure.test, screenshot));
    }
    controls::ScrollViewer viewer;
    viewer.Content(comparisons);
    viewer.HorizontalScrollMode(controls::ScrollMode::Disabled);
    viewer.VerticalScrollMode(controls::ScrollMode::Auto);
    viewer.VerticalScrollBarVisibility(controls::ScrollBarVisibility::Auto);
    controls::Grid::SetRow(viewer, 1);
    page.Children().Append(viewer);

    m_root.Children().Clear();
    m_root.Children().Append(page);
}

} // namespace tailgate::uwp::tests
