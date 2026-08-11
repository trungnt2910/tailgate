#pragma once

#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <utility>

#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.UI.Core.h>

#include <gtest/gtest.h>

#include "common/UwpAliases.h"

#include "TestResult.h"

namespace tailgate::uwp::tests
{

namespace streams = winrt::Windows::Storage::Streams;
namespace ui_core = winrt::Windows::UI::Core;

struct ScreenshotEnvironment final
{
    float logicalDpi;
    double textScaleFactor;
    bool highContrast;
    bool animationsEnabled;
};

enum class GoldenComparisonMode
{
    Perceptual,
    Exact,
};

class TestHost final
{
public:
    TestHost() = delete;

    inline static constexpr wchar_t OutputFileName[] = L"Tailgate.Tests.output.txt";
    inline static constexpr wchar_t ExitFileName[] = L"Tailgate.Tests.exit.txt";
    inline static constexpr wchar_t StandardLanguage[] = L"en-US";
    inline static constexpr double StandardViewportWidth = 1024.0;
    inline static constexpr double StandardViewportHeight = 768.0;
    inline static constexpr float StandardLogicalDpi = 96.0F;
    inline static constexpr double StandardTextScaleFactor = 1.0;
    inline static constexpr bool StandardAnimationsEnabled = false;

    static void Initialize(const ui_core::CoreDispatcher& dispatcher,
                           const controls::Grid& root,
                           const controls::Grid& surface,
                           const controls::TextBlock& status);

    template <typename Factory>
    [[nodiscard]] static foundation::IAsyncOperation<xaml::UIElement>
    SetTestContentAsync(Factory factory)
    {
        co_await winrt::resume_foreground(s_dispatcher);
        const xaml::UIElement content = factory();
        s_surface.Children().Clear();
        s_surface.Children().Append(content);
        s_surface.UpdateLayout();
        co_await s_dispatcher.RunIdleAsync(
            [](const ui_core::IdleDispatchedHandlerArgs&)
            {
            });
        co_return content;
    }

    [[nodiscard]] static foundation::IAsyncOperation<streams::IRandomAccessStream>
    CaptureTestContentAsync();

    [[nodiscard]] static foundation::IAsyncOperation<streams::IRandomAccessStream>
    CaptureTestContentAsync(const xaml::UIElement& content);

    [[nodiscard]] static foundation::IAsyncAction WaitForIdleAsync()
    {
        co_await winrt::resume_foreground(s_dispatcher);
        co_await s_dispatcher.RunIdleAsync(
            [](const ui_core::IdleDispatchedHandlerArgs&)
            {
            });
    }

    template <typename Function>
    static void RunOnUiThread(Function&& function)
    {
        if (s_dispatcher.HasThreadAccess())
        {
            std::invoke(std::forward<Function>(function));
            return;
        }
        std::exception_ptr error;
        s_dispatcher
            .RunAsync(ui_core::CoreDispatcherPriority::Normal,
                      [&function, &error]
                      {
                          try
                          {
                              std::invoke(std::forward<Function>(function));
                          }
                          catch (...)
                          {
                              error = std::current_exception();
                          }
                      })
            .get();
        if (error)
        {
            std::rethrow_exception(error);
        }
    }

    [[nodiscard]] static testing::AssertionResult
    CheckGolden(const xaml::UIElement& content,
                const winrt::hstring& goldenPath,
                GoldenComparisonMode mode = GoldenComparisonMode::Perceptual);

    [[nodiscard]] static testing::AssertionResult
    CheckGolden(const winrt::hstring& goldenPath,
                GoldenComparisonMode mode = GoldenComparisonMode::Perceptual);

    [[nodiscard]] static ScreenshotEnvironment Environment() noexcept;

    [[nodiscard]] static foundation::IAsyncAction
    CompleteTestRunAsync(const winrt::hstring& message, TestRunResult result);

private:
    [[nodiscard]] static testing::AssertionResult
    CheckCapturedGolden(const streams::IRandomAccessStream& capturedPng,
                        const winrt::hstring& goldenPath,
                        GoldenComparisonMode mode);

    static ui_core::CoreDispatcher s_dispatcher;
    static controls::Grid s_root;
    static controls::Grid s_surface;
    static controls::TextBlock s_status;
    static ScreenshotEnvironment s_environment;
    static std::shared_ptr<class TestResultDisplay> s_resultDisplay;
};

} // namespace tailgate::uwp::tests
