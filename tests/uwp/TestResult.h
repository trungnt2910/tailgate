#pragma once

#include <string>
#include <vector>

namespace tailgate::uwp::tests
{

struct FailedTestResult final
{
    std::wstring testSuite;
    std::wstring testName;
};

struct TestRunResult final
{
    int exitCode;
    std::vector<FailedTestResult> failedTests;
};

} // namespace tailgate::uwp::tests
