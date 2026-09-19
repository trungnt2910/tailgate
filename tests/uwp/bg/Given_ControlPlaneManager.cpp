#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "common/Settings.h"
#include "common/TcpSocketFactory.h"

#include "manager/impl/ControlPlaneManagerImpl.h"

#include "fakes/bg/manager/FakeSessionManager.h"
#include "fakes/control/client/FakeSession.h"

namespace tailgate::uwp::tests
{

class Given_ControlPlaneManager : public testing::Test
{
protected:
    void SetUp() override
    {
        for (std::size_t index = 0; index < m_names.size(); ++index)
        {
            m_values[index] = Settings::Get(m_names[index]);
            Settings::Remove(m_names[index]);
        }
    }

    void TearDown() override
    {
        for (std::size_t index = 0; index < m_names.size(); ++index)
        {
            if (m_values[index])
            {
                Settings::Set(m_names[index], m_values[index]);
            }
            else
            {
                Settings::Remove(m_names[index]);
            }
        }
    }

private:
    std::array<winrt::hstring, 3> m_names{L"RegistrationComplete", L"AuthKey", L"NodeFollowupUrl"};
    std::array<Settings::Value, 3> m_values{};
};

TEST_F(Given_ControlPlaneManager, When_MapsArriveSuccessfully_Then_ExistingControlStreamIsKept)
{
    auto state = std::make_shared<tailgate::tests::fakes::control::client::SessionState>();
    tailgate::types::netmap::NetworkConfig network;
    network.SelfKey("nodekey:" + std::string(64, '0'));
    network.SelfAddress("192.0.2.1");
    state->Registration.Network = network;
    state->Registration.NetworkMapStreaming = true;
    tailgate::tests::fakes::control::client::FakeSessionFactory factory(state);
    FakeSessionManager session;
    TcpSocketFactory sockets;
    bg::manager::ControlPlaneManagerImpl subject(session, factory, sockets);
    std::promise<void> secondRead;
    auto secondReadReady = secondRead.get_future();
    std::size_t reads = 0;
    state->WaitForMap = [&]() -> tailgate::types::netmap::NetworkConfig
    {
        if (++reads == 2)
        {
            secondRead.set_value();
            throw bg::manager::ControlIdentityChangedError();
        }
        return network;
    };
    const auto registration = subject.Connect("");
    ASSERT_TRUE(registration.Network.has_value());
    std::size_t updates = 0;

    subject.StartMaintenance(
        [&](auto)
        {
            ++updates;
        });
    const auto completed = secondReadReady.wait_for(std::chrono::seconds(10));
    subject.StopMaintenance();
    const auto registrations =
        std::count(state->Operations.begin(), state->Operations.end(), "register");

    EXPECT_EQ(completed, std::future_status::ready);
    EXPECT_EQ(reads, 2U);
    EXPECT_EQ(updates, 1U);
    EXPECT_EQ(registrations, 1);
}

TEST_F(Given_ControlPlaneManager,
       When_ResetCancelsPendingRead_Then_WorkerExitsBeforeSessionDestruction)
{
    auto state = std::make_shared<tailgate::tests::fakes::control::client::SessionState>();
    tailgate::types::netmap::NetworkConfig network;
    network.SelfKey("nodekey:" + std::string(64, '0'));
    network.SelfAddress("192.0.2.1");
    state->Registration.Network = network;
    state->Registration.NetworkMapStreaming = true;
    std::promise<void> reading;
    auto readStarted = reading.get_future();
    std::promise<void> cancellation;
    auto cancelled = cancellation.get_future();
    std::atomic_bool readExited = false;
    std::future_status cancellationStatus = std::future_status::timeout;
    bool destroyedAfterRead = false;
    state->WaitForMap = [&]()
    {
        reading.set_value();
        cancellationStatus = cancelled.wait_for(std::chrono::seconds(10));
        readExited = true;
        return network;
    };
    state->OnClose = [&]()
    {
        cancellation.set_value();
    };
    state->OnDestroy = [&]()
    {
        destroyedAfterRead = readExited.load();
    };
    tailgate::tests::fakes::control::client::FakeSessionFactory factory(state);
    FakeSessionManager session;
    TcpSocketFactory sockets;
    bg::manager::ControlPlaneManagerImpl subject(session, factory, sockets);
    const auto registration = subject.Connect("");
    ASSERT_TRUE(registration.Network.has_value());
    std::size_t updates = 0;

    subject.StartMaintenance(
        [&](auto)
        {
            ++updates;
        });
    const auto started = readStarted.wait_for(std::chrono::seconds(10));
    subject.Reset();

    EXPECT_EQ(started, std::future_status::ready);
    EXPECT_TRUE(state->Closed);
    EXPECT_TRUE(readExited.load());
    EXPECT_EQ(cancellationStatus, std::future_status::ready);
    EXPECT_TRUE(destroyedAfterRead);
    EXPECT_EQ(updates, 0U);
}

} // namespace tailgate::uwp::tests
