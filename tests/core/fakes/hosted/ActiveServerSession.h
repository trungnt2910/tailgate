#pragma once

#include <memory>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/ServerSession.h>

#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests::fakes
{

struct ActiveServerSession
{
    static constexpr std::uint64_t NodeId = 42;
    tailgate::di::Injector Injector;
    tailgate::crypto::Bytes32 ClientPrivateKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::crypto::Bytes32 ClientPublicKey =
        tailgate::crypto::X25519PublicFromPrivate(ClientPrivateKey);
    tailgate::crypto::Bytes32 RelayPrivateKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::crypto::Bytes32 RelayPublicKey =
        tailgate::crypto::X25519PublicFromPrivate(RelayPrivateKey);
    std::unique_ptr<tailgate::hosted::ServerSession> Session;
    tailgate::types::netmap::NetworkConfig Network;

    ActiveServerSession()
    {
        tailgate::tests::fakes::InstallFakeNetworkBindings(Injector);
        auto& factory = Injector.create<tailgate::hosted::ServerSessionFactory&>();
        Session = factory.CreateServerSession(tailgate::hosted::ServerSessionOptions{
            .ExpectedTailnet = "example.ts.net",
            .RelayHostName = "relay.example.ts.net",
            .RelayHostAddress = "100.64.0.10",
            .RelayPrivateKey = RelayPrivateKey,
            .RelayPublicKey = RelayPublicKey,
        });
        const tailgate::hosted::Challenge challenge =
            tailgate::hosted::ProtocolCodec::DecodeChallenge(
                Session->StartAuthentication().Payload());
        const tailgate::crypto::Bytes32 clientNonce = tailgate::crypto::GeneratePrivateKey();
        const tailgate::hosted::Authentication authentication(
            "example.ts.net",
            NodeId,
            "client.example.ts.net",
            "TestOS",
            "1",
            ClientPublicKey,
            clientNonce,
            tailgate::hosted::CreateClientProof(ClientPrivateKey,
                                                challenge.RelayPublicKey(),
                                                challenge.ServerNonce(),
                                                clientNonce));
        (void)Session->EvaluateAuthentication(tailgate::hosted::Frame(
            tailgate::hosted::MessageType::Authenticate,
            tailgate::hosted::ProtocolCodec::EncodeAuthentication(authentication)));
        (void)Session->CompleteAuthentication(true);
        Network.Domain("example.ts.net");
        Network.SelfNodeId(NodeId);
        Network.SelfKey("nodekey:" + tailgate::crypto::BytesToHex(ClientPublicKey.data(),
                                                                  ClientPublicKey.size()));
        Network.SelfAddress("100.64.0.1");
        Network.SelfName("client.example.ts.net");
        Network.MagicDnsDomain("example.ts.net");
        (void)Session->AcceptInitialNetworkMap(
            tailgate::hosted::Frame(tailgate::hosted::MessageType::NetworkMap,
                                    tailgate::hosted::ProtocolCodec::EncodeNetworkConfig(Network)));
    }
};

} // namespace tailgate::tests::fakes
