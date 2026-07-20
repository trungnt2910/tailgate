#include <memory>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "manager/impl/SessionManagerImpl.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_SessionManager : public testing::Test
{
protected:
    void SetUp() override
    {
        auto injector = di::make_injector();
        m_subject = injector.create<std::unique_ptr<bg::manager::SessionManagerImpl>>();
    }

    std::unique_ptr<bg::manager::SessionManagerImpl> m_subject;
};

TEST_F(Given_SessionManager, When_RequiredComponentsBecomeReady_Then_SessionIsRunning)
{
    const auto generation = m_subject->BeginConnect();
    const bg::manager::SessionEvent control{.Generation = generation,
                                            .Component =
                                                bg::manager::SessionComponent::ControlPlane,
                                            .Kind = bg::manager::SessionEventKind::Ready};
    const bg::manager::SessionEvent data{.Generation = generation,
                                         .Component = bg::manager::SessionComponent::DataPlane,
                                         .Kind = bg::manager::SessionEventKind::Ready};
    const bg::manager::SessionEvent platform{.Generation = generation,
                                             .Component = bg::manager::SessionComponent::Platform,
                                             .Kind = bg::manager::SessionEventKind::Ready};

    m_subject->Report(control);
    m_subject->Report(data);
    m_subject->Report(platform);

    EXPECT_EQ(m_subject->State(), bg::manager::SessionState::Running);
}

TEST_F(Given_SessionManager, When_OldGenerationReports_Then_CurrentSessionIsUnchanged)
{
    const auto oldGeneration = m_subject->BeginConnect();
    const auto currentGeneration = m_subject->BeginConnect();
    const bg::manager::SessionEvent stale{
        .Generation = oldGeneration,
        .Component = bg::manager::SessionComponent::ControlPlane,
        .Kind = bg::manager::SessionEventKind::TerminalFailure,
    };

    m_subject->Report(stale);

    EXPECT_EQ(m_subject->Generation(), currentGeneration);
    EXPECT_EQ(m_subject->State(), bg::manager::SessionState::Starting);
}

TEST_F(Given_SessionManager, When_AnyComponentFails_Then_FailureTakesPrecedence)
{
    const auto generation = m_subject->BeginConnect();
    const bg::manager::SessionEvent authentication{
        .Generation = generation,
        .Component = bg::manager::SessionComponent::ControlPlane,
        .Kind = bg::manager::SessionEventKind::AuthenticationRequired,
    };
    const bg::manager::SessionEvent failure{
        .Generation = generation,
        .Component = bg::manager::SessionComponent::DataPlane,
        .Kind = bg::manager::SessionEventKind::TerminalFailure,
    };

    m_subject->Report(authentication);
    m_subject->Report(failure);

    EXPECT_EQ(m_subject->State(), bg::manager::SessionState::Failed);
}

TEST_F(Given_SessionManager, When_AuthenticationIsRequired_Then_ItTakesPrecedenceOverRecovery)
{
    const auto generation = m_subject->BeginConnect();
    const bg::manager::SessionEvent recovering{
        .Generation = generation,
        .Component = bg::manager::SessionComponent::DataPlane,
        .Kind = bg::manager::SessionEventKind::Recovering,
    };
    const bg::manager::SessionEvent authentication{
        .Generation = generation,
        .Component = bg::manager::SessionComponent::ControlPlane,
        .Kind = bg::manager::SessionEventKind::AuthenticationRequired,
    };

    m_subject->Report(recovering);
    m_subject->Report(authentication);

    EXPECT_EQ(m_subject->State(), bg::manager::SessionState::AwaitingAuthentication);
}

TEST_F(Given_SessionManager, When_Stopping_Then_LateReportsAreIgnoredUntilComplete)
{
    const auto generation = m_subject->BeginConnect();
    const bg::manager::SessionEvent failure{
        .Generation = generation,
        .Component = bg::manager::SessionComponent::Platform,
        .Kind = bg::manager::SessionEventKind::TerminalFailure,
    };

    m_subject->BeginStop();
    m_subject->Report(failure);
    const auto stateBeforeComplete = m_subject->State();
    m_subject->CompleteStop();

    EXPECT_EQ(stateBeforeComplete, bg::manager::SessionState::Stopping);
    EXPECT_EQ(m_subject->State(), bg::manager::SessionState::Stopped);
    EXPECT_GT(m_subject->Generation(), generation);
}

} // namespace
} // namespace tailgate::uwp::tests
