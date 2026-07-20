#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <winrt/Windows.Storage.h>

#include "common/UwpAliases.h"
#include "common/UwpFireAndForget.h"

#include "TestResult.h"

namespace tailgate::uwp::tests
{

class TestResultDisplay final
{
public:
    TestResultDisplay(const controls::Grid& root,
                      winrt::hstring message,
                      winrt::hstring outputFileName,
                      TestRunResult result);

    [[nodiscard]] foundation::IAsyncAction ShowAsync();

private:
    struct DisplayedFailure final
    {
        FailedTestResult test;
        std::vector<storage::StorageFile> screenshots;
    };

    [[nodiscard]] controls::Grid CreateSummaryPage();
    FireAndForget OpenLogsAsync();
    void ShowSummary();
    FireAndForget ShowScreenshotsAsync(std::size_t failureIndex);

    controls::Grid m_root;
    winrt::hstring m_message;
    winrt::hstring m_outputFileName;
    TestRunResult m_result;
    std::vector<DisplayedFailure> m_failures;
};

} // namespace tailgate::uwp::tests
