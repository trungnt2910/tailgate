#include <memory>
#include <system_error>

#include <gtest/gtest.h>

#include <tailgate/crypto/PrefixedKey.h>
#include <tailgate/ipn/ipnlocal/DelegatedNode.h>

#include "fakes/derp/FakeConnection.h"
#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate
{
namespace
{

constexpr base::EventToken DeviceToken{.Value = 1};
constexpr base::EventToken DerpToken{.Value = 3};

class Given_DelegatedNode : public testing::Test, public ipn::ipnlocal::DerpTransportFactory
{
protected:
    void SetNetworkInterface(const std::string&) override
    {
    }

    Given_DelegatedNode()
    {
        tests::fakes::InstallFakeNetworkBindings(Injector);
        Network.SelfAddress("100.64.0.1");
        Network.SelfNodeId(1);
        Network.SelfKey("nodekey:" + std::string(64, '2'));
        Network.Domain("example.ts.net");
        Network.DerpRegion(1);
        Network.DerpHost("derp.example.com");
        Peer.Address("100.64.0.2");
        Peer.Name("peer.example.ts.net");
        Peer.Key("nodekey:" + std::string(64, '1'));
        Peer.DerpRegion(1);
        Peer.DerpHost("derp.example.com");
        Network.Peers({Peer});
        Subject = std::make_unique<ipn::ipnlocal::DelegatedNode>(
            Injector.create<wgengine::Session&>(),
            Injector.create<wgengine::Engine&>(),
            Injector.create<wgengine::magicsock::Connection&>(),
            *this,
            Injector.create<base::TimeProvider&>());
        Subject->Start(Network, {.Name = "test", .ReadinessToken = DeviceToken});
        Events().Next.Status = base::EventWaitStatus::Woken;
    }

    std::unique_ptr<derp::Connection>
    Create(int, const std::string&, bool, std::size_t, bool enabled) override
    {
        auto connection = std::make_unique<tests::fakes::derp::FakeConnection>(
            DerpToken, derp::DerpClient::Packet{});
        connection->SetEnabled(enabled);
        Relay = connection.get();
        return connection;
    }

    tests::fakes::FakeEventLoop& Events()
    {
        return dynamic_cast<tests::fakes::FakeEventLoop&>(Injector.create<base::EventLoop&>());
    }

    void Send(const crypto::Bytes32& peer, bool control)
    {
        Injector.create<tests::fakes::FakeDevice&>().Incoming.push_back(
            {.Result = wgengine::tstun::DeviceIoResult::Complete,
             .Packet = hosted::ProtocolCodec::EncodePeerPacket(
                 hosted::PeerPacket(peer, {1, 2, 3}, control, false))});
        Events().Next.Events.push_back(
            {.Token = DeviceToken, .Readiness = base::EventReadiness::Readable});
        (void)Subject->Wait(16, 16, 4096);
    }

    di::Injector Injector;
    types::netmap::NetworkConfig Network;
    types::netmap::PeerConfig Peer;
    tests::fakes::derp::FakeConnection* Relay = nullptr;
    std::unique_ptr<ipn::ipnlocal::DelegatedNode> Subject;
};

TEST_F(Given_DelegatedNode, When_KnownClientPacketArrives_Then_OpaqueBytesReachPeerThroughDerp)
{
    const auto key = crypto::PrefixedKey::TryParse(Peer.Key(), "nodekey:");
    ASSERT_TRUE(key.has_value());

    Send(*key, false);

    EXPECT_EQ(Relay->Sent.size(), 1U);
    EXPECT_EQ(Relay->Sent.at(0).Destination, *key);
    EXPECT_EQ(Relay->Sent.at(0).Payload, (std::vector<std::uint8_t>{1, 2, 3}));
    EXPECT_EQ(Relay->Sent.at(0).Priority, derp::DerpSendQueue::Priority::Data);
}

TEST_F(Given_DelegatedNode, When_ControlPacketArrives_Then_DerpControlPriorityIsPreserved)
{
    const auto key = crypto::PrefixedKey::TryParse(Peer.Key(), "nodekey:");
    ASSERT_TRUE(key.has_value());

    Send(*key, true);

    EXPECT_EQ(Relay->Sent.size(), 1U);
    EXPECT_EQ(Relay->Sent.at(0).Priority, derp::DerpSendQueue::Priority::Control);
}

TEST_F(Given_DelegatedNode, When_UnknownPeerIsRequested_Then_NoPacketIsForwarded)
{
    crypto::Bytes32 unknown{};

    Send(unknown, false);

    EXPECT_TRUE(Relay->Sent.empty());
}

TEST_F(Given_DelegatedNode, When_PeerIsRemoved_Then_PreviousDestinationIsNoLongerUsable)
{
    const auto key = crypto::PrefixedKey::TryParse(Peer.Key(), "nodekey:");
    ASSERT_TRUE(key.has_value());
    auto next = Network;
    next.Peers({});
    const auto update = hosted::Frame(hosted::MessageType::NetworkMap,
                                      hosted::ProtocolCodec::EncodeNetworkConfig(next))
                            .Encode();

    Subject->HandleControl(update);
    Send(*key, false);

    EXPECT_TRUE(Relay->Sent.empty());
}

TEST_F(Given_DelegatedNode, When_TwoControlFramesShareDatagram_Then_InvalidControlIsRejected)
{
    auto bytes = hosted::Frame(hosted::MessageType::Heartbeat, {}).Encode();
    const auto extra = bytes;
    bytes.insert(bytes.end(), extra.begin(), extra.end());

    const auto handle = [&]()
    {
        Subject->HandleControl(bytes);
    };

    EXPECT_THROW(handle(), std::system_error);
}

} // namespace

} // namespace tailgate
