#include <winrt/Windows.Foundation.h>

#include <gtest/gtest.h>

#include "common/WinrtOperation.h"

namespace tailgate::uwp::tests
{
namespace
{

using winrt::Windows::Foundation::IAsyncAction;

IAsyncAction CompletedAction()
{
    co_return;
}

IAsyncAction FailedAction()
{
    throw winrt::hresult_invalid_argument();
    co_return;
}

TEST(Given_WinrtOperation, When_CompletedRefreshIsConsumed_Then_RetryDoesNotAssignAnotherDelegate)
{
    IAsyncAction pending = CompletedAction();

    auto first = ConsumeAsyncAction(pending);
    auto retry = ConsumeAsyncAction(pending);

    EXPECT_FALSE(pending);
    EXPECT_NO_THROW(first.GetResults());
    EXPECT_NO_THROW(retry.GetResults());
}

TEST(Given_WinrtOperation, When_RefreshFails_Then_FailurePropagatesWithoutPoisoningRetry)
{
    IAsyncAction pending = FailedAction();

    auto first = ConsumeAsyncAction(pending);
    auto retry = ConsumeAsyncAction(pending);

    EXPECT_FALSE(pending);
    EXPECT_THROW(first.GetResults(), winrt::hresult_invalid_argument);
    EXPECT_NO_THROW(retry.GetResults());
}

TEST(Given_WinrtOperation, When_NewRefreshReplacesConsumedAction_Then_NextWaitObservesNewFailure)
{
    IAsyncAction pending = CompletedAction();

    auto first = ConsumeAsyncAction(pending);
    pending = FailedAction();
    auto next = ConsumeAsyncAction(pending);

    EXPECT_FALSE(pending);
    EXPECT_NO_THROW(first.GetResults());
    EXPECT_THROW(next.GetResults(), winrt::hresult_invalid_argument);
}

} // namespace
} // namespace tailgate::uwp::tests
