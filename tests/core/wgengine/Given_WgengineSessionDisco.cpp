#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Connection.h>

#include "fakes/derp/FakeConnection.h"
#include "fakes/di/FakeNetworkBindings.h"

namespace
{

using tailgate::tests::fakes::FakeEventLoop;
using tailgate::tests::fakes::FakeUdpSocketFactory;
using tailgate::tests::fakes::derp::FakeConnection;

constexpr tailgate::base::EventToken DerpToken{.Value = 601};
constexpr tailgate::base::EventToken MagicsockToken{.Value = 602};
constexpr std::size_t MaximumEvents = 8;
constexpr std::size_t MaximumPackets = 4;
constexpr std::size_t MaximumPacketSize = 4096;

class Given_WgengineSessionDisco : public testing::Test
{
protected:
    void SetUp() override
    {
        tailgate::tests::fakes::InstallFakeNetworkBindings(Injector);
        dynamic_cast<FakeEventLoop&>(Injector.create<tailgate::base::EventLoop&>()).Next.Status =
            tailgate::base::EventWaitStatus::Woken;
        auto& sockets = dynamic_cast<FakeUdpSocketFactory&>(
            Injector.create<tailgate::types::nettype::UdpSocketFactory&>());
        auto& udp = Injector.create<tailgate::wgengine::magicsock::Connection&>();
        ASSERT_TRUE(udp.Open({.BindEndpoint = {},
                              .NetworkInterface = std::nullopt,
                              .ReadinessToken = MagicsockToken}));
        Socket = sockets.States.front();
        tailgate::types::netmap::PeerConfig peer;
        peer.Key("nodekey:" + tailgate::crypto::BytesToHex(PeerKey.data(), PeerKey.size()));
        peer.DiscoKey("discokey:" + tailgate::crypto::BytesToHex(Remote.PublicKey().data(),
                                                                 Remote.PublicKey().size()));
        peer.DerpRegion(1);
        peer.Endpoints({Endpoint.ToString()});
        Session = &Injector.create<tailgate::wgengine::Session&>();
        Session->Configure({.NodePrivateKey = LocalKey,
                            .NodePublicKey = tailgate::crypto::X25519PublicFromPrivate(LocalKey),
                            .DiscoPrivateKey = DiscoKey,
                            .AdvertisedEndpoint = Advertised,
                            .HomeDerpRegion = 1,
                            .Peers = {peer},
                            .ExitNode = {}});
    }

    FakeConnection& ReceivePing(tailgate::base::EventToken token)
    {
        const auto transaction = Remote.NewTransactionId();
        auto connection = std::make_unique<FakeConnection>(
            token,
            tailgate::derp::DerpClient::Packet{
                .Source = PeerKey,
                .Payload = Remote.BuildPing(tailgate::crypto::X25519PublicFromPrivate(DiscoKey),
                                            transaction)});
        auto& result = *connection;
        (void)Session->AddDerpConnection(1, std::move(connection));
        Injector.create<tailgate::base::EventLoop&>().Post(
            {.Token = token, .Readiness = tailgate::base::EventReadiness::Readable});
        return result;
    }

    tailgate::di::Injector Injector;
    const tailgate::crypto::Bytes32 LocalKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 DiscoKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 PeerKey =
        tailgate::crypto::X25519PublicFromPrivate(tailgate::crypto::GeneratePrivateKey());
    tailgate::disco::Disco Remote{tailgate::crypto::GeneratePrivateKey(), PeerKey};
    const tailgate::net::Endpoint Endpoint{tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 2),
                                           41641};
    const tailgate::net::Endpoint Advertised{tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 1),
                                             41641};
    std::shared_ptr<tailgate::tests::fakes::FakeUdpSocketState> Socket;
    tailgate::wgengine::Session* Session = nullptr;
};

TEST_F(Given_WgengineSessionDisco, When_ColdPingArrivesOverDerp_Then_OpensReverseUdpPath)
{
    auto& derp = ReceivePing(DerpToken);

    const auto result = Session->Wait(MaximumEvents, MaximumPackets, MaximumPacketSize);
    ASSERT_EQ(Socket->Sent.size(), 1U);
    ASSERT_EQ(derp.Sent.size(), 2U);
    const auto probe = Remote.Parse(Socket->Sent.front().Payload);
    const auto pong = Remote.Parse(derp.Sent.front().Payload);
    const auto invitation = Remote.Parse(derp.Sent.back().Payload);
    ASSERT_TRUE(probe);
    ASSERT_TRUE(pong);
    ASSERT_TRUE(invitation);

    EXPECT_EQ(result.DiscoEvents.size(), 1U);
    EXPECT_EQ(Socket->Sent.front().Destination, Endpoint);
    EXPECT_EQ(probe->Type, tailgate::disco::Disco::MessageType::Ping);
    EXPECT_EQ(pong->Type, tailgate::disco::Disco::MessageType::Pong);
    EXPECT_EQ(invitation->Type, tailgate::disco::Disco::MessageType::CallMeMaybe);
    EXPECT_EQ(invitation->Endpoints, std::vector{Advertised});
    EXPECT_FALSE(
        Injector.create<tailgate::wgengine::magicsock::Connection&>().HasDirectPath(PeerKey));
}

TEST_F(Given_WgengineSessionDisco, When_DerpPingsRepeat_Then_ReverseProbesAreRateLimited)
{
    auto& first = ReceivePing(DerpToken);
    constexpr tailgate::base::EventToken SecondDerpToken{.Value = 603};
    auto& second = ReceivePing(SecondDerpToken);

    const auto result = Session->Wait(MaximumEvents, MaximumPackets, MaximumPacketSize);

    EXPECT_EQ(result.DiscoEvents.size(), 2U);
    EXPECT_EQ(Socket->Sent.size(), 1U);
    EXPECT_EQ(first.Sent.size() + second.Sent.size(), 3U);
}

} // namespace
