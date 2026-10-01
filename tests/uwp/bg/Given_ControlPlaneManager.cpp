#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <semaphore>
#include <stop_token>
#include <string>
#include <system_error>

#include <gtest/gtest.h>

#include "common/Settings.h"
#include "common/TcpSocketFactory.h"

#include "manager/impl/ControlPlaneManagerImpl.h"

#include "fakes/bg/manager/FakeSessionManager.h"
#include "fakes/control/client/FakeSession.h"

namespace tailgate::uwp::tests
{

namespace
{

class CancellableSessionFactory final : public tailgate::control::client::SessionFactory
{
public:
    std::unique_ptr<tailgate::control::client::Session>
    CreateSession(tailgate::control::client::SessionOptions options,
                  tailgate::types::nettype::TcpSocketFactory&) override
    {
        NetworkInterface = options.NetworkInterface;
        std::binary_semaphore stopped(0);
        const std::stop_callback cancelled(options.Cancellation,
                                           [&]
                                           {
                                               stopped.release();
                                           });
        Opening.set_value();
        Cancelled = stopped.try_acquire_for(std::chrono::seconds(10));
        throw std::system_error(
            std::make_error_code(Cancelled ? std::errc::operation_canceled : std::errc::timed_out));
    }

    std::promise<void> Opening;
    std::string NetworkInterface;
    bool Cancelled = false;
};

} // namespace

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

TEST_F(Given_ControlPlaneManager, When_StoppedDuringDial_Then_UninstalledSessionIsCancelled)
{
    CancellableSessionFactory factory;
    auto opening = factory.Opening.get_future();
    FakeSessionManager session;
    TcpSocketFactory sockets;
    bg::manager::ControlPlaneManagerImpl subject(session, factory, sockets);
    subject.Start(1, "example-adapter");
    auto connecting = std::async(std::launch::async,
                                 [&]
                                 {
                                     try
                                     {
                                         (void)subject.Connect("");
                                         return std::error_code{};
                                     }
                                     catch (const std::system_error& error)
                                     {
                                         return error.code();
                                     }
                                 });

    const auto started = opening.wait_for(std::chrono::seconds(10));
    subject.RequestStop();
    const auto error = connecting.get();

    EXPECT_EQ(started, std::future_status::ready);
    EXPECT_TRUE(factory.Cancelled);
    EXPECT_EQ(factory.NetworkInterface, "example-adapter");
    EXPECT_EQ(error, std::errc::operation_canceled);
    EXPECT_TRUE(subject.IsStopping());
}

TEST_F(Given_ControlPlaneManager, When_NativeEndpointsArePublished_Then_ReconnectRetainsThem)
{
    auto state = std::make_shared<tailgate::tests::fakes::control::client::SessionState>();
    tailgate::types::netmap::NetworkConfig network;
    network.SelfKey("nodekey:" + std::string(64, '0'));
    network.SelfAddress("100.64.0.1");
    state->Registration.Network = network;
    tailgate::tests::fakes::control::client::FakeSessionFactory factory(state);
    FakeSessionManager manager;
    TcpSocketFactory sockets;
    bg::manager::ControlPlaneManagerImpl subject(manager, factory, sockets);
    subject.Start(1, "test-adapter");
    (void)subject.Connect("");
    const std::vector<tailgate::control::client::MapEndpoint> endpoints{
        {.AddressPort = "192.0.2.1:12345", .Type = tailgate::control::client::EndpointType::Local}};

    subject.PublishEndpoints(endpoints);
    const auto published = state->Endpoints;
    state->Endpoints.clear();
    (void)subject.Connect("");
    ASSERT_EQ(published.size(), 1U);
    ASSERT_EQ(state->Endpoints.size(), 1U);

    EXPECT_EQ(published.front().AddressPort, endpoints.front().AddressPort);
    EXPECT_EQ(state->Endpoints.front().AddressPort, endpoints.front().AddressPort);
    EXPECT_EQ(state->Endpoints.front().Type, endpoints.front().Type);
}

TEST_F(Given_ControlPlaneManager,
       When_BootstrapDiscoversEndpointsAfterRegistration_Then_PublishesBeforeMaintenance)
{
    auto state = std::make_shared<tailgate::tests::fakes::control::client::SessionState>();
    tailgate::types::netmap::NetworkConfig network;
    network.SelfKey("nodekey:" + std::string(64, '0'));
    network.SelfAddress("100.64.0.1");
    network.DerpRegion(1);
    state->Registration.Network = network;
    state->Registration.NetworkMapStreaming = true;
    tailgate::tests::fakes::control::client::FakeSessionFactory factory(state);
    FakeSessionManager manager;
    TcpSocketFactory sockets;
    bg::manager::ControlPlaneManagerImpl subject(manager, factory, sockets);
    (void)subject.Connect("");
    ASSERT_EQ(state->PublishedEndpoints.size(), 1U);
    ASSERT_TRUE(state->PublishedEndpoints.front().empty());
    const std::vector<tailgate::control::client::MapEndpoint> endpoints{
        {.AddressPort = "203.0.113.1:45678", .Type = tailgate::control::client::EndpointType::Stun},
        {.AddressPort = "192.0.2.1:12345", .Type = tailgate::control::client::EndpointType::Local}};

    subject.PublishEndpoints(endpoints);
    ASSERT_EQ(state->PublishedEndpoints.size(), 2U);
    ASSERT_EQ(state->PublishedEndpoints.back().size(), 2U);

    EXPECT_EQ(state->PublishedEndpoints.back()[0].AddressPort, endpoints[0].AddressPort);
    EXPECT_EQ(state->PublishedEndpoints.back()[0].Type, endpoints[0].Type);
    EXPECT_EQ(state->PublishedEndpoints.back()[1].AddressPort, endpoints[1].AddressPort);
    EXPECT_EQ(state->PublishedEndpoints.back()[1].Type, endpoints[1].Type);
    EXPECT_EQ(state->PublishedDerpRegions, (std::vector<int>{1, 1}));
    EXPECT_FALSE(state->Closed);
}

TEST_F(Given_ControlPlaneManager,
       When_EndpointsChangeDuringMaintenance_Then_ReplacesOnlyControlStream)
{
    using tailgate::tests::fakes::control::client::SessionState;
    auto first = std::make_shared<SessionState>();
    auto second = std::make_shared<SessionState>();
    tailgate::types::netmap::NetworkConfig network;
    network.SelfKey("nodekey:" + std::string(64, '0'));
    network.SelfAddress("100.64.0.1");
    first->Registration.Network = network;
    second->Registration.Network = network;
    std::promise<void> firstReading;
    std::promise<void> secondReading;
    auto firstReady = firstReading.get_future();
    auto secondReady = secondReading.get_future();
    std::binary_semaphore firstClosed(0);
    std::binary_semaphore secondClosed(0);
    first->OnClose = [&]
    {
        firstClosed.release();
    };
    second->OnClose = [&]
    {
        secondClosed.release();
    };
    first->WaitForMap = [&]() -> tailgate::types::netmap::NetworkConfig
    {
        firstReading.set_value();
        firstClosed.acquire();
        throw std::system_error(std::make_error_code(std::errc::operation_canceled));
    };
    second->WaitForMap = [&]() -> tailgate::types::netmap::NetworkConfig
    {
        secondReading.set_value();
        secondClosed.acquire();
        throw std::system_error(std::make_error_code(std::errc::operation_canceled));
    };
    tailgate::tests::fakes::control::client::FakeSessionFactory factory(first);
    FakeSessionManager manager;
    TcpSocketFactory sockets;
    bg::manager::ControlPlaneManagerImpl subject(manager, factory, sockets);
    subject.Start(1, "test-adapter");
    (void)subject.Connect("");
    factory.QueueState(second);
    const std::vector<tailgate::control::client::MapEndpoint> endpoints{
        {.AddressPort = "192.0.2.1:45678", .Type = tailgate::control::client::EndpointType::Local}};

    subject.StartMaintenance(
        [](auto)
        {
        });
    const auto started = firstReady.wait_for(std::chrono::seconds(10));
    subject.PublishEndpoints(endpoints);
    const auto reconnected = secondReady.wait_for(std::chrono::seconds(10));
    const auto stopping = subject.IsStopping();
    subject.StopMaintenance();
    ASSERT_EQ(second->Endpoints.size(), 1U);

    EXPECT_EQ(started, std::future_status::ready);
    EXPECT_EQ(reconnected, std::future_status::ready);
    EXPECT_TRUE(first->Closed);
    EXPECT_FALSE(stopping);
    EXPECT_EQ(second->Endpoints.front().AddressPort, endpoints.front().AddressPort);
    EXPECT_EQ(second->Endpoints.front().Type, endpoints.front().Type);
}

} // namespace tailgate::uwp::tests
