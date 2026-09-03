#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/control/client/Session.h>
#include <tailgate/types/nettype/TcpSocket.h>

#include "impl/ConnectionImpl.h"

#include "fakes/base/FakeEventLoop.h"
#include "fakes/base/FakeTimeProvider.h"
#include "fakes/control/client/FakeSession.h"
#include "fakes/types/nettype/FakeTcpSocket.h"

namespace
{

constexpr tailgate::base::EventToken ControlToken{.Value = 500};
constexpr tailgate::base::EventToken DifferentToken{.Value = 501};
constexpr auto ControlSilenceTimeout = std::chrono::minutes(2);

tailgate::control::client::SessionOptions ControlOptions()
{
    tailgate::control::client::SessionOptions result;
    result.ReadinessToken = ControlToken;
    return result;
}

struct ControlConnectionContext
{
    ControlConnectionContext()
        : State(std::make_shared<tailgate::tests::fakes::control::client::SessionState>()),
          SessionFactory(State),
          Connection(ControlOptions(), SessionFactory, SocketFactory, TimeProvider, EventLoop)
    {
    }

    std::shared_ptr<tailgate::tests::fakes::control::client::SessionState> State;
    tailgate::tests::fakes::control::client::FakeSessionFactory SessionFactory;
    tailgate::tests::fakes::FakeTcpSocketFactory SocketFactory;
    tailgate::tests::fakes::FakeTimeProvider TimeProvider;
    tailgate::tests::fakes::FakeEventLoop EventLoop;
    tailgate::control::client::impl::ConnectionImpl Connection;
};

void ConfigureStreamingRegistration(ControlConnectionContext& context,
                                    int derpRegion,
                                    std::string domain = "reconnected.example.ts.net")
{
    tailgate::types::netmap::NetworkConfig network;
    network.Domain(std::move(domain));
    network.DerpRegion(derpRegion);
    context.State->Registration.Network = std::move(network);
    context.State->Registration.NetworkMapStreaming = true;
}

std::shared_ptr<tailgate::tests::fakes::control::client::SessionState>
ReplacementSession(int derpRegion, std::uint8_t generatedDiscoByte)
{
    auto result = std::make_shared<tailgate::tests::fakes::control::client::SessionState>();
    tailgate::types::netmap::NetworkConfig network;
    network.Domain("reconnected.example.ts.net");
    network.DerpRegion(derpRegion);
    result->Registration.Network = std::move(network);
    result->Registration.NetworkMapStreaming = true;
    tailgate::crypto::Bytes32 generatedDiscoKey{};
    generatedDiscoKey.fill(generatedDiscoByte);
    result->GeneratedDiscoPrivateKey = generatedDiscoKey;
    return result;
}

std::vector<tailgate::types::netmap::NetworkConfig>
CompleteReconnect(ControlConnectionContext& context)
{
    (void)context.Connection.Maintain();
    context.EventLoop.WaitForWake();
    return context.Connection.Maintain();
}

tailgate::control::client::ConnectionEventResult
CompleteReconnectAndProcessReadable(ControlConnectionContext& context)
{
    (void)CompleteReconnect(context);
    return context.Connection.ProcessEvent(tailgate::base::Event{
        .Token = ControlToken,
        .Readiness = tailgate::base::EventReadiness::Readable,
    });
}

} // namespace

TEST(Given_ControlConnectionEvents, When_StreamingStarts_Then_SessionBecomesNonBlocking)
{
    ControlConnectionContext context;

    context.Connection.StartStreaming();

    EXPECT_TRUE(context.State->NonBlocking);
}

TEST(Given_ControlConnectionEvents, When_UnrelatedTokenIsReadable_Then_NetworkMapIsNotPolled)
{
    ControlConnectionContext context;

    const tailgate::control::client::ConnectionEventResult result =
        context.Connection.ProcessEvent(tailgate::base::Event{
            .Token = DifferentToken,
            .Readiness = tailgate::base::EventReadiness::Readable,
        });

    EXPECT_FALSE(result.Handled);
    EXPECT_EQ(context.State->PollCalls, 0U);
}

TEST(Given_ControlConnectionEvents, When_WriteReadyWithoutTlsReadNeed_Then_NetworkMapIsNotPolled)
{
    ControlConnectionContext context;

    const tailgate::control::client::ConnectionEventResult result =
        context.Connection.ProcessEvent(tailgate::base::Event{
            .Token = ControlToken,
            .Readiness = tailgate::base::EventReadiness::Writable,
        });

    EXPECT_TRUE(result.Handled);
    EXPECT_TRUE(result.NetworkMaps.empty());
    EXPECT_EQ(context.State->PollCalls, 0U);
}

TEST(Given_ControlConnectionEvents, When_Readable_Then_AvailableMapsAreDrainedOnce)
{
    ControlConnectionContext context;
    tailgate::types::netmap::NetworkConfig first;
    first.Domain("first.example.ts.net");
    tailgate::types::netmap::NetworkConfig second;
    second.Domain("second.example.ts.net");
    context.State->NetworkMaps = {first, second};

    const tailgate::control::client::ConnectionEventResult result =
        context.Connection.ProcessEvent(tailgate::base::Event{
            .Token = ControlToken,
            .Readiness = tailgate::base::EventReadiness::Readable,
        });

    EXPECT_TRUE(result.Handled);
    EXPECT_EQ(result.NetworkMaps.size(), 2U);
    EXPECT_EQ(result.NetworkMaps[0].Domain(), "first.example.ts.net");
    EXPECT_EQ(result.NetworkMaps[1].Domain(), "second.example.ts.net");
    EXPECT_EQ(context.State->PollCalls, 3U);
}

TEST(Given_ControlConnectionEvents,
     When_StreamingConnectionReconnects_Then_StreamRestartsNonBlocking)
{
    ControlConnectionContext context;
    ConfigureStreamingRegistration(context, 5);
    context.Connection.SetPreferredDerp(5);
    context.Connection.StartStreaming();
    (void)context.Connection.ProcessEvent(tailgate::base::Event{
        .Token = ControlToken,
        .Readiness = tailgate::base::EventReadiness::Error,
    });
    context.State->Operations.clear();
    context.TimeProvider.Advance(std::chrono::seconds(1));

    const std::vector<tailgate::types::netmap::NetworkConfig> updates = CompleteReconnect(context);

    ASSERT_EQ(updates.size(), 1U);
    EXPECT_EQ(context.State->Operations,
              (std::vector<std::string>{
                  "register", "update-host-info", "set-preferred-derp", "enable-nonblocking"}));
    EXPECT_EQ(context.State->PollCalls, 0U);
}

TEST(Given_ControlConnectionEvents,
     When_RegistrationAlreadyStreams_Then_ReconnectRestoresStreamingDerp)
{
    ControlConnectionContext context;
    ConfigureStreamingRegistration(context, 5);
    (void)context.Connection.RegisterUntilAuthorized({}, {});
    context.Connection.StartStreaming();
    (void)context.Connection.ProcessEvent(tailgate::base::Event{
        .Token = ControlToken,
        .Readiness = tailgate::base::EventReadiness::Error,
    });
    context.State->Operations.clear();
    context.TimeProvider.Advance(std::chrono::seconds(1));

    const std::vector<tailgate::types::netmap::NetworkConfig> updates = CompleteReconnect(context);

    ASSERT_EQ(updates.size(), 1U);
    EXPECT_EQ(context.State->Operations,
              (std::vector<std::string>{
                  "register", "update-host-info", "set-preferred-derp", "enable-nonblocking"}));
}

TEST(Given_ControlConnectionEvents,
     When_ReconnectIsPrepared_Then_ReadinessActivatesOnlyAfterSessionIsAdopted)
{
    ControlConnectionContext context;
    ConfigureStreamingRegistration(context, 5);
    context.Connection.StartStreaming();
    (void)context.Connection.ProcessEvent(tailgate::base::Event{
        .Token = ControlToken,
        .Readiness = tailgate::base::EventReadiness::Error,
    });
    std::optional<bool> connectedWhenNonBlocking;
    context.State->NonBlockingChanged = [&](bool enabled)
    {
        if (enabled)
        {
            connectedWhenNonBlocking = context.Connection.Connected();
        }
    };
    context.TimeProvider.Advance(std::chrono::seconds(1));

    const std::vector<tailgate::types::netmap::NetworkConfig> updates = CompleteReconnect(context);

    EXPECT_EQ(updates.size(), 1U);
    EXPECT_EQ(connectedWhenNonBlocking, std::optional<bool>(true));
}

TEST(Given_ControlConnectionEvents, When_ReconnectedStreamBecomesReadable_Then_BufferedMapIsDrained)
{
    ControlConnectionContext context;
    ConfigureStreamingRegistration(context, 5);
    tailgate::types::netmap::NetworkConfig network;
    network.Domain("reconnected.example.ts.net");
    context.Connection.SetPreferredDerp(5);
    context.Connection.StartStreaming();
    (void)context.Connection.ProcessEvent(tailgate::base::Event{
        .Token = ControlToken,
        .Readiness = tailgate::base::EventReadiness::Error,
    });
    context.State->NetworkMaps.push_back(network);
    context.State->Operations.clear();
    context.TimeProvider.Advance(std::chrono::seconds(1));

    const tailgate::control::client::ConnectionEventResult result =
        CompleteReconnectAndProcessReadable(context);
    const std::vector<tailgate::types::netmap::NetworkConfig>& updates = result.NetworkMaps;
    const std::string domain = updates.empty() ? std::string{} : updates.front().Domain();

    EXPECT_EQ(updates.size(), 1U);
    EXPECT_EQ(domain, "reconnected.example.ts.net");
    EXPECT_EQ(context.State->Operations,
              (std::vector<std::string>{
                  "register", "update-host-info", "set-preferred-derp", "enable-nonblocking"}));
    EXPECT_EQ(context.State->PollCalls, 2U);
}

TEST(Given_ControlConnectionEvents, When_WriteReadyWithPendingOutput_Then_ControlIoIsAdvanced)
{
    ControlConnectionContext context;
    context.State->PendingOutput = true;

    const tailgate::control::client::ConnectionEventResult result =
        context.Connection.ProcessEvent(tailgate::base::Event{
            .Token = ControlToken,
            .Readiness = tailgate::base::EventReadiness::Writable,
        });

    EXPECT_TRUE(result.Handled);
    EXPECT_EQ(context.State->PollCalls, 1U);
    EXPECT_TRUE(context.State->WriteInterest);
}

TEST(Given_ControlConnectionEvents,
     When_ReconnectRegistrationIsPending_Then_MaintainReturnsWithoutBlocking)
{
    ControlConnectionContext context;
    ConfigureStreamingRegistration(context, 5);
    std::mutex mutex;
    std::condition_variable condition;
    bool registrationEntered = false;
    bool registrationReleased = false;
    context.State->BeforeRegister = [&]()
    {
        std::unique_lock lock(mutex);
        registrationEntered = true;
        condition.notify_all();
        condition.wait(lock,
                       [&]()
                       {
                           return registrationReleased;
                       });
    };
    context.Connection.StartStreaming();
    (void)context.Connection.ProcessEvent(tailgate::base::Event{
        .Token = ControlToken,
        .Readiness = tailgate::base::EventReadiness::Error,
    });
    context.TimeProvider.Advance(std::chrono::seconds(1));

    (void)context.Connection.Maintain();
    {
        std::unique_lock lock(mutex);
        condition.wait(lock,
                       [&]()
                       {
                           return registrationEntered;
                       });
        registrationReleased = true;
    }
    condition.notify_all();
    context.EventLoop.WaitForWake();
    const std::vector<tailgate::types::netmap::NetworkConfig> updates =
        context.Connection.Maintain();

    EXPECT_TRUE(registrationEntered);
    EXPECT_EQ(updates.size(), 1U);
}

TEST(Given_ControlConnectionEvents,
     When_RegisteredKeyReconnectsAfterTransportError_Then_KeyIsPreserved)
{
    ControlConnectionContext context;
    ConfigureStreamingRegistration(context, 5);
    context.State->DiscoPrivateKey.fill(3);
    (void)context.Connection.RegisterUntilAuthorized({}, {});
    const tailgate::crypto::Bytes32 registeredKey = context.Connection.DiscoPrivateKey();
    auto replacement = ReplacementSession(5, 7);
    context.SessionFactory.QueueState(replacement);
    context.Connection.StartStreaming();

    (void)context.Connection.ProcessEvent(tailgate::base::Event{
        .Token = ControlToken,
        .Readiness = tailgate::base::EventReadiness::Error,
    });
    context.TimeProvider.Advance(std::chrono::seconds(1));
    const std::vector<tailgate::types::netmap::NetworkConfig> updates = CompleteReconnect(context);

    ASSERT_EQ(updates.size(), 1U);
    EXPECT_EQ(replacement->DiscoPrivateKey, registeredKey);
}

TEST(Given_ControlConnectionEvents,
     When_RegisteredKeyReconnectsAfterStreamSilence_Then_KeyIsPreserved)
{
    ControlConnectionContext context;
    ConfigureStreamingRegistration(context, 5);
    context.State->DiscoPrivateKey.fill(3);
    (void)context.Connection.RegisterUntilAuthorized({}, {});
    const tailgate::crypto::Bytes32 registeredKey = context.Connection.DiscoPrivateKey();
    auto replacement = ReplacementSession(5, 7);
    context.SessionFactory.QueueState(replacement);
    context.Connection.StartStreaming();

    context.TimeProvider.Advance(ControlSilenceTimeout);
    (void)context.Connection.Maintain();
    context.TimeProvider.Advance(std::chrono::seconds(1));
    const std::vector<tailgate::types::netmap::NetworkConfig> updates = CompleteReconnect(context);

    ASSERT_EQ(updates.size(), 1U);
    EXPECT_EQ(replacement->DiscoPrivateKey, registeredKey);
}
