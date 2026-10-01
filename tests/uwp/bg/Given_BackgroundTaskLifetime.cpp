#include <gtest/gtest.h>

#include <winrt/Windows.ApplicationModel.Background.h>
#include <winrt/Windows.Foundation.h>

#include "bg/BackgroundTaskLifetime.h"

namespace
{
namespace background = winrt::Windows::ApplicationModel::Background;

struct FakeDeferral : winrt::implements<FakeDeferral, background::IBackgroundTaskDeferral>
{
    void Complete()
    {
        ++Completions;
    }

    int Completions = 0;
};

struct FakeTask : winrt::implements<FakeTask, background::IBackgroundTaskInstance>
{
    winrt::guid InstanceId() const
    {
        return Id;
    }

    background::BackgroundTaskRegistration Task() const
    {
        return nullptr;
    }

    std::uint32_t Progress() const
    {
        return 0;
    }

    void Progress(std::uint32_t)
    {
    }

    winrt::Windows::Foundation::IInspectable TriggerDetails() const
    {
        return nullptr;
    }

    std::uint32_t SuspendedCount() const
    {
        return 0;
    }

    background::BackgroundTaskDeferral GetDeferral()
    {
        ++Deferrals;
        return Deferral.as<background::BackgroundTaskDeferral>();
    }

    winrt::event_token Canceled(const background::BackgroundTaskCanceledEventHandler&)
    {
        return {.value = 1};
    }

    void Canceled(winrt::event_token) noexcept
    {
    }

    winrt::guid Id{L"11111111-1111-1111-1111-111111111111"};
    winrt::com_ptr<FakeDeferral> Deferral = winrt::make_self<FakeDeferral>();
    int Deferrals = 0;
};

class Given_BackgroundTaskLifetime : public testing::Test
{
protected:
    winrt::com_ptr<FakeTask> Task = winrt::make_self<FakeTask>();
};

TEST_F(Given_BackgroundTaskLifetime, When_DispatchIsRunning_Then_DeferralIsHeld)
{
    const auto task = Task.as<background::IBackgroundTaskInstance>();

    const tailgate::uwp::bg::BackgroundTaskLifetime lifetime(task);

    EXPECT_EQ(Task->Deferrals, 1);
    EXPECT_EQ(Task->Deferral->Completions, 0);
}

TEST_F(Given_BackgroundTaskLifetime, When_DispatchReturns_Then_DeferralCompletes)
{
    const auto task = Task.as<background::IBackgroundTaskInstance>();

    {
        const tailgate::uwp::bg::BackgroundTaskLifetime lifetime(task);
    }

    EXPECT_EQ(Task->Deferrals, 1);
    EXPECT_EQ(Task->Deferral->Completions, 1);
}

TEST_F(Given_BackgroundTaskLifetime, When_LaterDispatchReturns_Then_EachDeferralCompletes)
{
    auto later = winrt::make_self<FakeTask>();
    later->Id = winrt::guid{L"22222222-2222-2222-2222-222222222222"};

    {
        const tailgate::uwp::bg::BackgroundTaskLifetime first(
            Task.as<background::IBackgroundTaskInstance>());
    }
    {
        const tailgate::uwp::bg::BackgroundTaskLifetime second(
            later.as<background::IBackgroundTaskInstance>());
    }

    EXPECT_EQ(Task->Deferrals, 1);
    EXPECT_EQ(later->Deferrals, 1);
    EXPECT_EQ(Task->Deferral->Completions, 1);
    EXPECT_EQ(later->Deferral->Completions, 1);
}

TEST_F(Given_BackgroundTaskLifetime, When_DispatchThrows_Then_DeferralCompletes)
{
    const auto dispatch = [&]
    {
        const tailgate::uwp::bg::BackgroundTaskLifetime lifetime(
            Task.as<background::IBackgroundTaskInstance>());
        throw winrt::hresult_invalid_argument();
    };

    try
    {
        dispatch();
    }
    catch (const winrt::hresult_invalid_argument&)
    {
    }

    EXPECT_EQ(Task->Deferrals, 1);
    EXPECT_EQ(Task->Deferral->Completions, 1);
}

} // namespace
