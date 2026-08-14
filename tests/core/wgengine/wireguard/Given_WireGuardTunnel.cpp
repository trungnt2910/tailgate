#include <gtest/gtest.h>

#include <tailgate/protocol/Crypto.h>
#include <tailgate/protocol/WireGuardTunnel.h>

TEST(Given_WireGuardHandshake, When_TimerRunsImmediately_Then_InitiationIsNotReplaced)
{
    tailgate::protocol::WireGuardTunnel::Key privateKey{};
    privateKey[1] = 1;
    tailgate::protocol::WireGuardTunnel::Key peerPrivateKey{};
    peerPrivateKey[1] = 2;
    const auto peerPublicKey = tailgate::protocol::X25519PublicFromPrivate(peerPrivateKey);

    tailgate::protocol::WireGuardTunnel tunnel(privateKey);
    const auto peer = tunnel.AddPeer(peerPublicKey, {}, 10, true);
    const bool initiallySessionless = !tunnel.HasSession(peer);
    const auto initialTimerAction = tunnel.UpdateTimers(peer);
    const std::vector<std::uint8_t> initiation = tunnel.CreateHandshake(peer);
    const auto subsequentTimerAction = tunnel.UpdateTimers(peer);

    EXPECT_TRUE(initiallySessionless);
    EXPECT_EQ(initialTimerAction, tailgate::protocol::WireGuardTunnel::TimerAction::SendHandshake);
    EXPECT_EQ(initiation.size(), 148U);
    EXPECT_EQ(subsequentTimerAction, tailgate::protocol::WireGuardTunnel::TimerAction::None);
}

TEST(Given_WireGuardPeerInitiates, When_PacketIsProcessed_Then_ResponderCanExchangeData)
{
    tailgate::protocol::WireGuardTunnel::Key firstPrivateKey{};
    firstPrivateKey[1] = 1;
    tailgate::protocol::WireGuardTunnel::Key secondPrivateKey{};
    secondPrivateKey[1] = 2;

    tailgate::protocol::WireGuardTunnel first(firstPrivateKey);
    tailgate::protocol::WireGuardTunnel second(secondPrivateKey);
    const auto firstPeer =
        first.AddPeer(tailgate::protocol::X25519PublicFromPrivate(secondPrivateKey));
    const auto secondPeer =
        second.AddPeer(tailgate::protocol::X25519PublicFromPrivate(firstPrivateKey));

    const auto initiation = first.CreateHandshake(firstPeer);
    const auto accepted = second.ProcessPacket(secondPeer, initiation);
    ASSERT_TRUE(accepted.has_value());
    const auto completed = first.ProcessPacket(firstPeer, accepted->Reply);
    ASSERT_TRUE(completed.has_value());
    const auto confirmed = second.ProcessPacket(secondPeer, completed->Reply);
    const std::vector<std::uint8_t> plaintext{0x45, 0x00, 0x00, 0x04};
    const auto encrypted = first.Encrypt(firstPeer, plaintext);
    const auto decrypted = second.ProcessPacket(secondPeer, encrypted);
    ASSERT_TRUE(decrypted.has_value());

    EXPECT_TRUE(accepted->SessionEstablished);
    EXPECT_EQ(accepted->Reply.size(), 92U);
    EXPECT_TRUE(completed->SessionEstablished);
    EXPECT_FALSE(completed->Reply.empty());
    EXPECT_TRUE(confirmed.has_value());
    EXPECT_EQ(decrypted->Plaintext, plaintext);
}

TEST(Given_EstablishedWireGuardSession, When_SendingKeepalive_Then_EmptyPayloadRoundTrips)
{
    tailgate::protocol::WireGuardTunnel::Key firstPrivateKey{};
    firstPrivateKey[1] = 1;
    tailgate::protocol::WireGuardTunnel::Key secondPrivateKey{};
    secondPrivateKey[1] = 2;
    tailgate::protocol::WireGuardTunnel first(firstPrivateKey);
    tailgate::protocol::WireGuardTunnel second(secondPrivateKey);
    const auto firstPeer =
        first.AddPeer(tailgate::protocol::X25519PublicFromPrivate(secondPrivateKey));
    const auto secondPeer =
        second.AddPeer(tailgate::protocol::X25519PublicFromPrivate(firstPrivateKey));
    const auto initiation = first.CreateHandshake(firstPeer);
    const auto accepted = second.ProcessPacket(secondPeer, initiation);
    ASSERT_TRUE(accepted.has_value());
    const auto completed = first.ProcessPacket(firstPeer, accepted->Reply);
    ASSERT_TRUE(completed.has_value());
    const bool confirmationAccepted =
        second.ProcessPacket(secondPeer, completed->Reply).has_value();
    const std::vector<std::uint8_t> encrypted = first.Encrypt(firstPeer, {});
    const auto decrypted = second.ProcessPacket(secondPeer, encrypted);
    ASSERT_TRUE(decrypted.has_value());

    EXPECT_TRUE(confirmationAccepted);
    EXPECT_TRUE(decrypted->Plaintext.empty());
}

TEST(Given_EstablishedWireGuardSession, When_Rekeyed_Then_BidirectionalDataUsesNewSession)
{
    tailgate::protocol::WireGuardTunnel::Key initiatorPrivateKey{};
    initiatorPrivateKey[1] = 1;
    tailgate::protocol::WireGuardTunnel::Key responderPrivateKey{};
    responderPrivateKey[1] = 2;
    tailgate::protocol::WireGuardTunnel initiator(initiatorPrivateKey);
    tailgate::protocol::WireGuardTunnel responder(responderPrivateKey);
    const auto initiatorPeer =
        initiator.AddPeer(tailgate::protocol::X25519PublicFromPrivate(responderPrivateKey));
    const auto responderPeer =
        responder.AddPeer(tailgate::protocol::X25519PublicFromPrivate(initiatorPrivateKey));
    const auto initialInitiation = initiator.CreateHandshake(initiatorPeer);
    const auto initialResponse = responder.ProcessPacket(responderPeer, initialInitiation);
    ASSERT_TRUE(initialResponse.has_value());
    const auto initialCompletion = initiator.ProcessPacket(initiatorPeer, initialResponse->Reply);
    ASSERT_TRUE(initialCompletion.has_value());
    const bool initialConfirmationAccepted =
        responder.ProcessPacket(responderPeer, initialCompletion->Reply).has_value();
    const auto rekeyInitiation = initiator.CreateHandshake(initiatorPeer);
    const auto rekeyResponse = responder.ProcessPacket(responderPeer, rekeyInitiation);
    ASSERT_TRUE(rekeyResponse.has_value());
    const auto rekeyCompletion = initiator.ProcessPacket(initiatorPeer, rekeyResponse->Reply);
    ASSERT_TRUE(rekeyCompletion.has_value());
    const bool rekeyConfirmationAccepted =
        responder.ProcessPacket(responderPeer, rekeyCompletion->Reply).has_value();
    const std::vector<std::uint8_t> request{0x45, 0x00, 0x00, 0x04};
    const auto encryptedRequest = initiator.Encrypt(initiatorPeer, request);
    const auto decryptedRequest = responder.ProcessPacket(responderPeer, encryptedRequest);
    ASSERT_TRUE(decryptedRequest.has_value());
    const std::vector<std::uint8_t> response{0x45, 0x00, 0x00, 0x05, 0x00};
    const auto encryptedResponse = responder.Encrypt(responderPeer, response);
    const auto decryptedResponse = initiator.ProcessPacket(initiatorPeer, encryptedResponse);
    ASSERT_TRUE(decryptedResponse.has_value());

    EXPECT_TRUE(initialConfirmationAccepted);
    EXPECT_TRUE(rekeyResponse->SessionEstablished);
    EXPECT_TRUE(rekeyConfirmationAccepted);
    EXPECT_EQ(decryptedRequest->Plaintext, request);
    EXPECT_EQ(decryptedResponse->Plaintext, response);
}

TEST(Given_DuplicateHandshakeInitiation, When_OneResponseIsConfirmed_Then_SessionRemainsUsable)
{
    tailgate::protocol::WireGuardTunnel::Key initiatorPrivateKey{};
    initiatorPrivateKey[1] = 1;
    tailgate::protocol::WireGuardTunnel::Key responderPrivateKey{};
    responderPrivateKey[1] = 2;
    tailgate::protocol::WireGuardTunnel initiator(initiatorPrivateKey);
    tailgate::protocol::WireGuardTunnel responder(responderPrivateKey);
    const auto initiatorPeer =
        initiator.AddPeer(tailgate::protocol::X25519PublicFromPrivate(responderPrivateKey));
    const auto responderPeer =
        responder.AddPeer(tailgate::protocol::X25519PublicFromPrivate(initiatorPrivateKey));
    const std::vector<std::uint8_t> initiation = initiator.CreateHandshake(initiatorPeer);

    const auto firstResponse = responder.ProcessPacket(responderPeer, initiation);
    const auto duplicateResponse = responder.ProcessPacket(responderPeer, initiation);
    ASSERT_TRUE(firstResponse.has_value());
    const auto completion = initiator.ProcessPacket(initiatorPeer, firstResponse->Reply);
    ASSERT_TRUE(completion.has_value());
    const bool confirmationAccepted =
        responder.ProcessPacket(responderPeer, completion->Reply).has_value();
    const std::vector<std::uint8_t> request{0x45, 0x00, 0x00, 0x04};
    const auto encryptedRequest = initiator.Encrypt(initiatorPeer, request);
    const auto decryptedRequest = responder.ProcessPacket(responderPeer, encryptedRequest);
    ASSERT_TRUE(decryptedRequest.has_value());

    EXPECT_FALSE(duplicateResponse.has_value());
    EXPECT_TRUE(confirmationAccepted);
    EXPECT_EQ(decryptedRequest->Plaintext, request);
}

TEST(Given_MorePeersThanOneUpstreamDevice, When_Added_Then_TunnelShardsThem)
{
    tailgate::protocol::WireGuardTunnel::Key privateKey{};
    privateKey[1] = 1;
    tailgate::protocol::WireGuardTunnel tunnel(privateKey);
    bool allPeersSessionless = true;

    for (std::uint8_t index = 2; index < 24; ++index)
    {
        tailgate::protocol::WireGuardTunnel::Key peerPrivateKey{};
        peerPrivateKey[1] = index;
        const auto peer =
            tunnel.AddPeer(tailgate::protocol::X25519PublicFromPrivate(peerPrivateKey));
        allPeersSessionless = allPeersSessionless && !tunnel.HasSession(peer);
    }

    EXPECT_TRUE(allPeersSessionless);
}

TEST(Given_SharedTransportWithMultiplePeers, When_InitiationArrives_Then_PeerIsIdentified)
{
    tailgate::protocol::WireGuardTunnel::Key receiverPrivateKey{};
    receiverPrivateKey[1] = 1;
    tailgate::protocol::WireGuardTunnel::Key firstPrivateKey{};
    firstPrivateKey[1] = 2;
    tailgate::protocol::WireGuardTunnel::Key secondPrivateKey{};
    secondPrivateKey[1] = 3;
    tailgate::protocol::WireGuardTunnel receiver(receiverPrivateKey);
    (void)receiver.AddPeer(tailgate::protocol::X25519PublicFromPrivate(firstPrivateKey));
    const auto secondPeer =
        receiver.AddPeer(tailgate::protocol::X25519PublicFromPrivate(secondPrivateKey));
    tailgate::protocol::WireGuardTunnel sender(secondPrivateKey);
    const auto receiverPeer =
        sender.AddPeer(tailgate::protocol::X25519PublicFromPrivate(receiverPrivateKey));
    const std::vector<std::uint8_t> initiation = sender.CreateHandshake(receiverPeer);

    const auto received = receiver.ProcessPacket(initiation);
    ASSERT_TRUE(received.has_value());

    EXPECT_EQ(received->Peer, secondPeer);
    EXPECT_TRUE(received->SessionEstablished);
}
