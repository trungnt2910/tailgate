#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Tsmp.h>
#include <tailgate/wgengine/ping/Tracker.h>

#include "fakes/di/FakeNetworkBindings.h"

namespace
{

constexpr std::uint64_t RequestId = 42;

std::string KeyText(const std::string& prefix, const tailgate::crypto::Bytes32& key)
{
    return prefix + tailgate::crypto::BytesToHex(key.data(), key.size());
}

tailgate::types::netmap::NetworkConfig Network(const tailgate::crypto::Bytes32& nodeKey,
                                               const tailgate::crypto::Bytes32& discoKey)
{
    tailgate::types::netmap::PeerConfig peer;
    peer.Name("peer.example.ts.net");
    peer.Address("100.64.0.2");
    peer.Key(KeyText("nodekey:", nodeKey));
    peer.DiscoKey(KeyText("discokey:", discoKey));
    peer.DerpCode("example-relay");
    tailgate::types::netmap::NetworkConfig result;
    result.SelfAddress("100.64.0.1");
    result.Peers({std::move(peer)});
    return result;
}

struct Subject
{
    tailgate::di::Injector Injector;
    tailgate::wgengine::ping::Tracker* Tracker = nullptr;

    Subject()
    {
        tailgate::tests::fakes::InstallFakeNetworkBindings(Injector);
        Tracker = &Injector.create<tailgate::wgengine::ping::Tracker&>();
    }
};

} // namespace

TEST(Given_PingTracker, When_DiscoPingStarts_Then_PortableProbeIsBuilt)
{
    Subject subject;
    const tailgate::crypto::Bytes32 localNodeKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 remoteNodeKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::disco::Disco localDisco(tailgate::crypto::GeneratePrivateKey(), localNodeKey);
    tailgate::disco::Disco remoteDisco(tailgate::crypto::GeneratePrivateKey(), remoteNodeKey);
    const tailgate::types::netmap::NetworkConfig network =
        Network(remoteNodeKey, remoteDisco.PublicKey());
    const tailgate::wgengine::ping::Request request{
        .Id = RequestId,
        .Target = "peer",
        .PingMode = tailgate::wgengine::ping::Mode::Disco,
        .Timeout = std::chrono::seconds(5),
        .Relay = "hosted-relay",
    };

    const tailgate::wgengine::ping::StartResult result =
        subject.Tracker->Start(request, network, localDisco, {});
    const std::optional<tailgate::disco::Disco::Message> message =
        result.Outbound ? remoteDisco.Parse(result.Outbound->Payload) : std::nullopt;

    ASSERT_TRUE(result.Outbound.has_value());
    ASSERT_TRUE(message.has_value());
    EXPECT_EQ(result.Status, tailgate::wgengine::ping::StartStatus::Ready);
    EXPECT_EQ(result.Outbound->RequestId, RequestId);
    EXPECT_EQ(result.Outbound->Peer, remoteNodeKey);
    EXPECT_TRUE(result.Outbound->Disco);
    EXPECT_EQ(message->Type, tailgate::disco::Disco::MessageType::Ping);
}

TEST(Given_PingTracker, When_MatchingDiscoPongCompletes_Then_MetadataAndLatencyAreReturned)
{
    Subject subject;
    const tailgate::crypto::Bytes32 localNodeKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 remoteNodeKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::disco::Disco localDisco(tailgate::crypto::GeneratePrivateKey(), localNodeKey);
    tailgate::disco::Disco remoteDisco(tailgate::crypto::GeneratePrivateKey(), remoteNodeKey);
    const tailgate::types::netmap::NetworkConfig network =
        Network(remoteNodeKey, remoteDisco.PublicKey());
    constexpr auto Started = tailgate::wgengine::ping::Tracker::TimePoint(std::chrono::seconds(2));
    constexpr auto Latency = std::chrono::milliseconds(17);
    const tailgate::wgengine::ping::Request request{
        .Id = RequestId,
        .Target = "peer.example.ts.net",
        .PingMode = tailgate::wgengine::ping::Mode::Disco,
        .Timeout = std::chrono::seconds(5),
        .Relay = "hosted-relay",
    };
    const tailgate::wgengine::ping::StartResult started =
        subject.Tracker->Start(request, network, localDisco, Started);
    ASSERT_TRUE(started.Outbound.has_value());
    const std::optional<tailgate::disco::Disco::Message> ping =
        remoteDisco.Parse(started.Outbound->Payload);
    ASSERT_TRUE(ping.has_value());

    const std::optional<tailgate::wgengine::ping::Result> result =
        subject.Tracker->CompleteDisco(remoteNodeKey, ping->Transaction, 443, Started + Latency);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->RequestId, RequestId);
    EXPECT_TRUE(result->Responded);
    EXPECT_EQ(result->Latency, Latency);
    EXPECT_EQ(result->PeerName, "peer.example.ts.net");
    EXPECT_EQ(result->PeerAddress, "100.64.0.2");
    EXPECT_EQ(result->Relay, "hosted-relay");
    EXPECT_EQ(result->PeerApiPort, 443);
}

TEST(Given_PingTracker, When_RequestExpires_Then_TypedTimeoutResultIsReturnedOnce)
{
    Subject subject;
    const tailgate::crypto::Bytes32 localNodeKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 remoteNodeKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::disco::Disco localDisco(tailgate::crypto::GeneratePrivateKey(), localNodeKey);
    tailgate::disco::Disco remoteDisco(tailgate::crypto::GeneratePrivateKey(), remoteNodeKey);
    const tailgate::types::netmap::NetworkConfig network =
        Network(remoteNodeKey, remoteDisco.PublicKey());
    constexpr auto Timeout = std::chrono::seconds(5);
    const tailgate::wgengine::ping::Request request{
        .Id = RequestId,
        .Target = "peer",
        .PingMode = tailgate::wgengine::ping::Mode::Disco,
        .Timeout = Timeout,
        .Relay = {},
    };
    const tailgate::wgengine::ping::StartResult started =
        subject.Tracker->Start(request, network, localDisco, {});
    ASSERT_TRUE(started.Outbound.has_value());
    const auto deadline = tailgate::wgengine::ping::Tracker::TimePoint(Timeout);

    const std::vector<tailgate::wgengine::ping::Result> expired = subject.Tracker->Expire(deadline);
    const std::vector<tailgate::wgengine::ping::Result> expiredAgain =
        subject.Tracker->Expire(deadline + Timeout);

    ASSERT_EQ(expired.size(), 1U);
    EXPECT_EQ(expired.front().RequestId, RequestId);
    EXPECT_FALSE(expired.front().Responded);
    EXPECT_EQ(expired.front().Latency, Timeout);
    EXPECT_TRUE(expiredAgain.empty());
}

TEST(Given_PingTracker, When_TsmpPongCompletes_Then_PeerApiPortIsReturned)
{
    Subject subject;
    const tailgate::crypto::Bytes32 localNodeKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 remoteNodeKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::disco::Disco localDisco(tailgate::crypto::GeneratePrivateKey(), localNodeKey);
    tailgate::disco::Disco remoteDisco(tailgate::crypto::GeneratePrivateKey(), remoteNodeKey);
    const tailgate::types::netmap::NetworkConfig network =
        Network(remoteNodeKey, remoteDisco.PublicKey());
    constexpr auto Started = tailgate::wgengine::ping::Tracker::TimePoint(std::chrono::seconds(2));
    const tailgate::wgengine::ping::Request request{
        .Id = RequestId,
        .Target = "100.64.0.2",
        .PingMode = tailgate::wgengine::ping::Mode::Tsmp,
        .Timeout = std::chrono::seconds(5),
        .Relay = {},
    };
    const tailgate::wgengine::ping::StartResult started =
        subject.Tracker->Start(request, network, localDisco, Started);
    ASSERT_TRUE(started.Outbound.has_value());
    const std::optional<std::vector<std::uint8_t>> pongPacket =
        tailgate::net::packet::TsmpPacket::BuildPong(started.Outbound->Payload, 8080);
    ASSERT_TRUE(pongPacket.has_value());
    const std::optional<tailgate::net::packet::TsmpPong> pong =
        tailgate::net::packet::TsmpPacket::ParsePong(*pongPacket);
    ASSERT_TRUE(pong.has_value());

    const std::optional<tailgate::wgengine::ping::Result> result = subject.Tracker->CompleteTsmp(
        pong->Token(), pong->PeerApiPort(), Started + std::chrono::milliseconds(3));

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->Responded);
    EXPECT_EQ(result->PeerAddress, "100.64.0.2");
    EXPECT_EQ(result->PeerApiPort, 8080);
    EXPECT_FALSE(started.Outbound->Disco);
}

TEST(Given_PingTracker, When_PeerNodeKeyIsInvalid_Then_ProbeIsRejected)
{
    Subject subject;
    tailgate::disco::Disco disco(tailgate::crypto::GeneratePrivateKey(),
                                 tailgate::crypto::GeneratePrivateKey());
    tailgate::types::netmap::PeerConfig peer;
    peer.Name("peer.example.ts.net");
    peer.Address("100.64.0.2");
    peer.Key("nodekey:invalid");
    peer.DiscoKey("discokey:invalid");
    tailgate::types::netmap::NetworkConfig network;
    network.Peers({std::move(peer)});
    const tailgate::wgengine::ping::Request request{
        .Id = RequestId,
        .Target = "peer",
        .PingMode = tailgate::wgengine::ping::Mode::Disco,
        .Timeout = std::chrono::seconds(5),
        .Relay = {},
    };

    const tailgate::wgengine::ping::StartResult result =
        subject.Tracker->Start(request, network, disco, {});

    EXPECT_EQ(result.Status, tailgate::wgengine::ping::StartStatus::NoNodeKey);
    EXPECT_FALSE(result.Outbound.has_value());
}

TEST(Given_PingTracker, When_PeerDoesNotExist_Then_NoProbeIsTracked)
{
    Subject subject;
    tailgate::disco::Disco disco(tailgate::crypto::GeneratePrivateKey(),
                                 tailgate::crypto::GeneratePrivateKey());
    const tailgate::types::netmap::NetworkConfig network;
    const tailgate::wgengine::ping::Request request{
        .Id = RequestId,
        .Target = "missing.example.ts.net",
        .PingMode = tailgate::wgengine::ping::Mode::Disco,
        .Timeout = std::chrono::seconds(5),
        .Relay = {},
    };

    const tailgate::wgengine::ping::StartResult result =
        subject.Tracker->Start(request, network, disco, {});
    const std::vector<tailgate::wgengine::ping::Result> expired = subject.Tracker->Expire(
        tailgate::wgengine::ping::Tracker::TimePoint(std::chrono::seconds(10)));

    EXPECT_EQ(result.Status, tailgate::wgengine::ping::StartStatus::NoMatchingPeer);
    EXPECT_FALSE(result.Outbound.has_value());
    EXPECT_TRUE(expired.empty());
}
