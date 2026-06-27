#include <gtest/gtest.h>

#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/WireGuardTunnel.h"

TEST(Tailgate, GivenWireGuardHandshake_WhenTimerRunsImmediately_ThenInitiationIsNotReplaced)
{
    tailgate::protocol::WireGuardTunnel::Key privateKey{};
    privateKey[0] = 1;
    tailgate::protocol::WireGuardTunnel::Key peerPrivateKey{};
    peerPrivateKey[0] = 2;
    const auto peerPublicKey = tailgate::protocol::X25519PublicFromPrivate(peerPrivateKey);

    tailgate::protocol::WireGuardTunnel tunnel(privateKey);
    const auto peer = tunnel.AddPeer(peerPublicKey, {}, 10, true);
    ASSERT_TRUE(!tunnel.HasSession(peer));
    ASSERT_TRUE(tunnel.UpdateTimers(peer) ==
                tailgate::protocol::WireGuardTunnel::TimerAction::SendHandshake);
    const std::vector<std::uint8_t> initiation = tunnel.CreateHandshake(peer);

    ASSERT_TRUE(initiation.size() == 148);
    ASSERT_TRUE(tunnel.UpdateTimers(peer) ==
                tailgate::protocol::WireGuardTunnel::TimerAction::None);
}

TEST(Tailgate, GivenWireGuardPeerInitiates_WhenPacketIsProcessed_ThenResponderCanExchangeData)
{
    tailgate::protocol::WireGuardTunnel::Key firstPrivateKey{};
    firstPrivateKey[0] = 1;
    tailgate::protocol::WireGuardTunnel::Key secondPrivateKey{};
    secondPrivateKey[0] = 2;

    tailgate::protocol::WireGuardTunnel first(firstPrivateKey);
    tailgate::protocol::WireGuardTunnel second(secondPrivateKey);
    const auto firstPeer =
        first.AddPeer(tailgate::protocol::X25519PublicFromPrivate(secondPrivateKey));
    const auto secondPeer =
        second.AddPeer(tailgate::protocol::X25519PublicFromPrivate(firstPrivateKey));

    const auto initiation = first.CreateHandshake(firstPeer);
    const auto accepted = second.ProcessPacket(secondPeer, initiation);
    ASSERT_TRUE(accepted.has_value());
    ASSERT_TRUE(accepted->SessionEstablished);
    ASSERT_TRUE(accepted->Reply.size() == 92);

    const auto completed = first.ProcessPacket(firstPeer, accepted->Reply);
    ASSERT_TRUE(completed.has_value());
    ASSERT_TRUE(completed->SessionEstablished);

    const std::vector<std::uint8_t> plaintext{0x45, 0x00, 0x00, 0x04};
    const auto encrypted = first.Encrypt(firstPeer, plaintext);
    const auto decrypted = second.ProcessPacket(secondPeer, encrypted);
    ASSERT_TRUE(decrypted.has_value());
    ASSERT_TRUE(decrypted->Plaintext == plaintext);
}

TEST(Tailgate, GivenMorePeersThanOneUpstreamDevice_WhenAdded_ThenTunnelShardsThem)
{
    tailgate::protocol::WireGuardTunnel::Key privateKey{};
    privateKey[0] = 1;
    tailgate::protocol::WireGuardTunnel tunnel(privateKey);

    for (std::uint8_t index = 2; index < 24; ++index)
    {
        tailgate::protocol::WireGuardTunnel::Key peerPrivateKey{};
        peerPrivateKey[0] = index;
        const auto peer =
            tunnel.AddPeer(tailgate::protocol::X25519PublicFromPrivate(peerPrivateKey));
        ASSERT_TRUE(!tunnel.HasSession(peer));
    }
}
