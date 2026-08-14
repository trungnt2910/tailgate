#include <chrono>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/base/Clock.h>
#include <tailgate/di/Bindings.h>

namespace
{

class FakeClock final : public tailgate::base::IClock
{
public:
    explicit FakeClock(TimePoint now) : m_now(now)
    {
    }

    [[nodiscard]] TimePoint Now() const noexcept override
    {
        return m_now;
    }

private:
    TimePoint m_now;
};

} // namespace

TEST(Given_CoreBindings, When_ResolvingClockTwice_Then_SessionSharesOneInstance)
{
    auto injector = boost::di::make_injector(tailgate::di::Bindings());

    const auto* first = &injector.create<tailgate::base::IClock&>();
    const auto* second = &injector.create<tailgate::base::IClock&>();

    EXPECT_EQ(first, second);
}

TEST(Given_CoreBindings, When_CreatingSeparateSessions_Then_ClockStateDoesNotLeak)
{
    auto firstSession = boost::di::make_injector(tailgate::di::Bindings());
    auto secondSession = boost::di::make_injector(tailgate::di::Bindings());

    const auto* first = &firstSession.create<tailgate::base::IClock&>();
    const auto* second = &secondSession.create<tailgate::base::IClock&>();

    EXPECT_NE(first, second);
}

TEST(Given_CoreBindings, When_TestOverridesClock_Then_FakeCapabilityIsInjected)
{
    constexpr tailgate::base::IClock::TimePoint Now{std::chrono::seconds(42)};
    FakeClock clock(Now);
    auto injector = boost::di::make_injector(
        tailgate::di::Bindings(),
        boost::di::bind<tailgate::base::IClock>.to(clock)[boost::di::override]);

    const auto result = injector.create<tailgate::base::IClock&>().Now();

    EXPECT_EQ(result, Now);
}
