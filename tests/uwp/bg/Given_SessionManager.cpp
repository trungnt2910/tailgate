#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>

#include <boost/di.hpp>
#include <gtest/gtest.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>

#include "common/AuthorizationState.h"

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

    void TearDown() override
    {
        std::error_code error;
        (void)std::filesystem::remove(StatePath(), error);
    }

    [[nodiscard]] static std::filesystem::path StatePath()
    {
        const auto folder =
            winrt::Windows::Storage::ApplicationData::Current().LocalFolder().Path();
        return std::filesystem::path(folder.c_str()) / L"tailgate-state.json";
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

TEST_F(Given_SessionManager, When_LoginNotificationIsSent_Then_ForegroundReceivesControlUrl)
{
    const winrt::hstring tailgateServer = L"relay.example.com";
    const std::string authorizationUrl = "https://login.tailscale.com/a/fake-login-code";
    AuthorizationStateReceiver receiver(tailgateServer);
    const auto generation = m_subject->BeginConnect();
    const bg::manager::ForegroundConnectionNotification notification{
        .Kind = bg::manager::ForegroundConnectionKind::LoginRequired,
        .Url = authorizationUrl,
        .TailgateServer = winrt::to_string(tailgateServer),
    };

    m_subject->Notify(generation, notification);
    const std::vector<ConnectionMessage> messages = receiver.ReadAvailable();
    ASSERT_EQ(messages.size(), 1U);

    EXPECT_EQ(messages.front().Kind, ConnectionMessageKind::LoginRequired);
    EXPECT_EQ(messages.front().Url, winrt::to_hstring(authorizationUrl));
    EXPECT_EQ(messages.front().TailgateServer, tailgateServer);
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

TEST_F(Given_SessionManager, When_NetworkMapIsWritten_Then_NodeIdsArePersistedExactly)
{
    constexpr std::uint64_t SelfNodeId = 9'007'199'254'740'993ULL;
    constexpr std::uint64_t PeerNodeId = 18'446'744'073'709'551'614ULL;
    tailgate::types::netmap::NetworkConfig config;
    config.SelfNodeId(SelfNodeId);
    config.SelfName("local.example.ts.net");
    tailgate::types::netmap::PeerConfig peer;
    peer.NodeId(PeerNodeId);
    peer.Name("peer.example.ts.net");
    config.Peers({peer});

    m_subject->WriteState(config);

    std::ifstream stream(StatePath());
    const std::string text(std::istreambuf_iterator<char>(stream), {});
    const auto state = winrt::Windows::Data::Json::JsonObject::Parse(winrt::to_hstring(text));
    const auto devices = state.GetNamedArray(L"Devices");
    ASSERT_EQ(devices.Size(), 2U);
    EXPECT_EQ(devices.GetObjectAt(0).GetNamedString(L"NodeID"), winrt::to_hstring(SelfNodeId));
    EXPECT_EQ(devices.GetObjectAt(1).GetNamedString(L"NodeID"), winrt::to_hstring(PeerNodeId));
}

} // namespace
} // namespace tailgate::uwp::tests
