#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

#define WIN32_MEAN_AND_LEAN
#include <windows.h>
#ifdef GetCurrentTime
#undef GetCurrentTime
#endif

#include <winrt/Windows.ApplicationModel.Activation.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.System.Threading.h>
#include <winrt/Windows.UI.Xaml.Controls.h>
#include <winrt/Windows.UI.Xaml.h>
#include <winrt/base.h>

#include <gtest/gtest.h>

#include "common/Arguments.h"

#include "TestHost.h"
#include "TestResult.h"

namespace activation = tailgate::uwp::activation;
namespace controls = tailgate::uwp::controls;
namespace foundation = tailgate::uwp::foundation;
namespace storage = tailgate::uwp::storage;
namespace xaml = tailgate::uwp::xaml;
namespace threading = winrt::Windows::System::Threading;

namespace
{

class ScreenshotTestEnvironment final : public testing::Environment
{
public:
    void SetUp() override
    {
        const auto environment = tailgate::uwp::tests::TestHost::Environment();

        ASSERT_FALSE(environment.highContrast);
        ASSERT_FLOAT_EQ(tailgate::uwp::tests::TestHost::StandardLogicalDpi, environment.logicalDpi);
        ASSERT_DOUBLE_EQ(tailgate::uwp::tests::TestHost::StandardTextScaleFactor,
                         environment.textScaleFactor);
        ASSERT_EQ(tailgate::uwp::tests::TestHost::StandardAnimationsEnabled,
                  environment.animationsEnabled);
    }
};

constexpr char TestProgramName[] = "Tailgate.Tests";
constexpr wchar_t OutputCaptureFailureMessage[] = L"Could not capture GoogleTest output.";
constexpr wchar_t TestsPassedMessage[] = L"All UWP tests passed.";
constexpr wchar_t TestsFailedMessage[] = L"UWP tests failed.";
std::atomic<int> TestExitCode = EXIT_FAILURE;

bool RedirectGoogleTestOutput()
{
    const auto folder = storage::ApplicationData::Current().TemporaryFolder();
    const std::filesystem::path path = std::filesystem::path(folder.Path().c_str()) /
                                       tailgate::uwp::tests::TestHost::OutputFileName;
    std::FILE* output = nullptr;
    return _wfreopen_s(&output, path.c_str(), L"w", stdout) == 0;
}

std::vector<tailgate::uwp::tests::FailedTestResult> CollectFailedTests()
{
    std::vector<tailgate::uwp::tests::FailedTestResult> failures;
    const auto* unitTest = testing::UnitTest::GetInstance();
    for (int suiteIndex = 0; suiteIndex < unitTest->total_test_suite_count(); ++suiteIndex)
    {
        const auto* suite = unitTest->GetTestSuite(suiteIndex);
        for (int testIndex = 0; testIndex < suite->total_test_count(); ++testIndex)
        {
            const auto* test = suite->GetTestInfo(testIndex);
            if (!test->result()->Failed())
            {
                continue;
            }
            failures.push_back(tailgate::uwp::tests::FailedTestResult{
                .testSuite = winrt::to_hstring(test->test_suite_name()).c_str(),
                .testName = winrt::to_hstring(test->name()).c_str(),
            });
        }
    }
    return failures;
}

void CompleteTestRun(int exitCode,
                     const winrt::hstring& message,
                     bool exitWhenComplete,
                     std::vector<tailgate::uwp::tests::FailedTestResult> failures = {})
{
    TestExitCode.store(exitCode);
    const auto folder = storage::ApplicationData::Current().TemporaryFolder();
    const auto exitCodeFile =
        folder
            .CreateFileAsync(tailgate::uwp::tests::TestHost::ExitFileName,
                             storage::CreationCollisionOption::ReplaceExisting)
            .get();
    storage::FileIO::WriteTextAsync(exitCodeFile, winrt::to_hstring(exitCode)).get();
    tailgate::uwp::tests::TestHost::CompleteTestRunAsync(message,
                                                         tailgate::uwp::tests::TestRunResult{
                                                             .exitCode = exitCode,
                                                             .failedTests = std::move(failures),
                                                         },
                                                         exitWhenComplete)
        .get();
}

void RunTests(std::vector<std::string> arguments, bool exitWhenComplete)
{
    if (!RedirectGoogleTestOutput())
    {
        CompleteTestRun(EXIT_FAILURE, OutputCaptureFailureMessage, exitWhenComplete);
        return;
    }

    std::vector<char*> rawArguments;
    rawArguments.reserve(arguments.size() + 1);
    for (auto& argument : arguments)
    {
        rawArguments.push_back(argument.data());
    }
    const int suppliedArgumentCount = static_cast<int>(rawArguments.size());
    rawArguments.push_back(nullptr);
    int argumentCount = suppliedArgumentCount;
    testing::InitGoogleTest(&argumentCount, rawArguments.data());
    testing::AddGlobalTestEnvironment(new ScreenshotTestEnvironment);
    const int exitCode = RUN_ALL_TESTS();
    auto failures = CollectFailedTests();
    std::fflush(stdout);
    std::fclose(stdout);
    CompleteTestRun(exitCode,
                    exitCode == EXIT_SUCCESS ? TestsPassedMessage : TestsFailedMessage,
                    exitWhenComplete,
                    std::move(failures));
}

} // namespace

namespace winrt::Tailgate::Tests::implementation
{

struct App : xaml::ApplicationT<App>
{
    App()
    {
        RequestedTheme(xaml::ApplicationTheme::Light);
    }

    void OnLaunched(const activation::LaunchActivatedEventArgs&)
    {
        StartTests(std::vector<std::string>{TestProgramName}, false);
    }

    void OnActivated(const activation::IActivatedEventArgs& args)
    {
        if (args.Kind() == activation::ActivationKind::Protocol)
        {
            const auto protocolArgs = args.as<activation::ProtocolActivatedEventArgs>();
            StartTests(tailgate::uwp::Arguments::FromUri(protocolArgs.Uri()), true);
            return;
        }
        StartTests(std::vector<std::string>{TestProgramName}, false);
    }

private:
    void StartTests(std::vector<std::string> arguments, bool exitWhenComplete)
    {
        if (m_started)
        {
            return;
        }
        m_started = true;

        const auto window = xaml::Window::Current();
        const controls::Grid root;
        const controls::Grid testSurface;
        const controls::TextBlock status;
        status.Text(L"Running UWP tests...");
        root.Children().Append(testSurface);
        root.Children().Append(status);
        tailgate::uwp::tests::TestHost::Initialize(window.Dispatcher(), root, testSurface, status);
        window.Content(root);
        window.Activate();
        m_testRun = threading::ThreadPool::RunAsync(
            [arguments = std::move(arguments),
             exitWhenComplete](const foundation::IAsyncAction&) mutable
            {
                winrt::init_apartment(winrt::apartment_type::multi_threaded);
                RunTests(std::move(arguments), exitWhenComplete);
                winrt::uninit_apartment();
            });
    }

    bool m_started = false;
    foundation::IAsyncAction m_testRun{nullptr};
};

} // namespace winrt::Tailgate::Tests::implementation

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    winrt::init_apartment();
    xaml::Application::Start(
        [](auto&&)
        {
            winrt::make<winrt::Tailgate::Tests::implementation::App>();
        });
    return TestExitCode.load();
}
