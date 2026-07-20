#include <string>
#include <vector>

#include <winrt/Windows.Foundation.h>

#include <gtest/gtest.h>

#include "common/Arguments.h"

namespace tailgate::uwp::tests
{

TEST(Given_Arguments, When_QueryContainsFlagsAndValues_Then_ArgumentsMatchCliForm)
{
    const winrt::Windows::Foundation::Uri uri(
        L"tailgate://SET?hostname=host.example.ts.net&reset&exit-node=&--=192.0.2.1");

    const std::vector<std::string> arguments = Arguments::FromUri(uri);

    EXPECT_EQ(
        arguments,
        (std::vector<std::string>{
            "set", "--hostname=host.example.ts.net", "--reset", "--exit-node=", "192.0.2.1"}));
}

TEST(Given_Arguments, When_QueryIsEscaped_Then_NamesAndValuesAreDecoded)
{
    const winrt::Windows::Foundation::Uri uri(
        L"tailgate-tests://run?gtest_filter=Given_TestHost%2E%2A&label=hello+world");

    const std::vector<std::string> arguments = Arguments::FromUri(uri);

    EXPECT_EQ(arguments,
              (std::vector<std::string>{
                  "run", "--gtest_filter=Given_TestHost.*", "--label=hello world"}));
}

TEST(Given_Arguments, When_ValueContainsEscapedPercent_Then_PercentIsPreserved)
{
    const winrt::Windows::Foundation::Uri uri(L"tailgate-tests://run?gtest_filter=Given_%25GG");

    const std::vector<std::string> arguments = Arguments::FromUri(uri);

    EXPECT_EQ(arguments, (std::vector<std::string>{"run", "--gtest_filter=Given_%GG"}));
}

} // namespace tailgate::uwp::tests
