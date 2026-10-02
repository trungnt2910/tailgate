#include <stdexcept>
#include <vector>

#include <gtest/gtest.h>

#include "bg/manager/ProfileRecoveryManager.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_ProfileRecoveryManager : public testing::Test
{
protected:
    enum class Event
    {
        Enter,
        Leave,
        Request,
        Terminate,
        AuthorizeRedial
    };

    class Manager final : public bg::manager::ProfileRecoveryManager
    {
    public:
        void EnterConnect() override
        {
            Events.push_back(Event::Enter);
        }

        void LeaveConnect() override
        {
            Events.push_back(Event::Leave);
        }

        bool Request() override
        {
            Events.push_back(Event::Request);
            return Allowed;
        }

        void AttemptTerminated() override
        {
            Events.push_back(Event::AuthorizeRedial);
        }

        void RunPending(std::stop_token) override
        {
        }

        void Disconnecting() override
        {
        }

        void Connected() override
        {
        }

        bool Allowed = true;
        std::vector<Event> Events;
    } Recovery;
};

TEST_F(Given_ProfileRecoveryManager, When_RecoveryIsQueued_Then_TerminatesBeforeAuthorizingRedial)
{
    Recovery.Allowed = true;

    Recovery.FinishFailedConnect(
        [&]
        {
            Recovery.Events.push_back(Event::Terminate);
        });

    EXPECT_EQ(Recovery.Events,
              (std::vector<Event>{Event::Request, Event::Terminate, Event::AuthorizeRedial}));
}

TEST_F(Given_ProfileRecoveryManager, When_RecoveryIsDeclined_Then_StillTerminatesFailedConnect)
{
    Recovery.Allowed = false;

    Recovery.FinishFailedConnect(
        [&]
        {
            Recovery.Events.push_back(Event::Terminate);
        });

    EXPECT_EQ(Recovery.Events, (std::vector<Event>{Event::Request, Event::Terminate}));
}

TEST_F(Given_ProfileRecoveryManager, When_TerminationThrows_Then_DoesNotAuthorizeRedial)
{
    bool failed = false;

    try
    {
        Recovery.FinishFailedConnect(
            [&]
            {
                Recovery.Events.push_back(Event::Terminate);
                throw std::runtime_error("test termination failure");
            });
    }
    catch (const std::runtime_error&)
    {
        failed = true;
    }

    EXPECT_TRUE(failed);
    EXPECT_EQ(Recovery.Events, (std::vector<Event>{Event::Request, Event::Terminate}));
}

TEST_F(Given_ProfileRecoveryManager,
       When_ConnectScopeExits_Then_ReleasesCallbackBeforeDispatchRecovery)
{
    using Scope = bg::manager::ProfileRecoveryManager::ConnectScope;

    {
        const Scope scope(Recovery);
    }

    EXPECT_EQ(Recovery.Events, (std::vector<Event>{Event::Enter, Event::Leave}));
}

} // namespace
} // namespace tailgate::uwp::tests
