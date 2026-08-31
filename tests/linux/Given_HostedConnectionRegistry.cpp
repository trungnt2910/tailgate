#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/types/netmap/NetworkMap.h>

#include "HostedConnectionRegistry.h"

namespace
{

constexpr std::uint64_t HostedNodeId = 42;

tailgate::types::netmap::NetworkConfig NetworkMapFor(const tailgate::crypto::Bytes32& nodePublicKey)
{
    tailgate::types::netmap::NetworkConfig config;
    config.Domain("example.ts.net");
    config.SelfName("relay.example.ts.net");
    tailgate::types::netmap::PeerConfig peer;
    peer.NodeId(HostedNodeId);
    peer.Key("nodekey:" + tailgate::crypto::BytesToHex(nodePublicKey.data(), nodePublicKey.size()));
    config.Peers({std::move(peer)});
    return config;
}

} // namespace

TEST(Given_HostedConnectionRegistry, When_VisibleConnectionIsRegistered_Then_HostedPathIsAvailable)
{
    tailgate::linux_frontend::HostedConnectionRegistry registry;
    const tailgate::crypto::Bytes32 nodePublicKey = tailgate::crypto::GeneratePrivateKey();
    registry.UpdateNetworkMap(NetworkMapFor(nodePublicKey));
    tailgate::linux_frontend::HostedConnectionRegistrationResult registration = registry.Register(
        "fake-profile",
        []
        {
        },
        HostedNodeId);

    const bool visible = registry.IsNodeVisible("example.ts.net", HostedNodeId, nodePublicKey);
    const std::optional<std::string> path = registry.PathForNode(HostedNodeId);

    EXPECT_TRUE(visible);
    EXPECT_EQ(path, "tailgate(relay)");
}

TEST(Given_HostedConnectionRegistry, When_NodeIdentityDoesNotMatch_Then_NodeIsNotVisible)
{
    tailgate::linux_frontend::HostedConnectionRegistry registry;
    const tailgate::crypto::Bytes32 nodePublicKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 otherPublicKey = tailgate::crypto::GeneratePrivateKey();
    registry.UpdateNetworkMap(NetworkMapFor(nodePublicKey));

    const bool wrongTailnet =
        registry.IsNodeVisible("other.example.ts.net", HostedNodeId, nodePublicKey);
    const bool wrongNode =
        registry.IsNodeVisible("example.ts.net", HostedNodeId + 1, nodePublicKey);
    const bool wrongKey = registry.IsNodeVisible("example.ts.net", HostedNodeId, otherPublicKey);

    EXPECT_FALSE(wrongTailnet);
    EXPECT_FALSE(wrongNode);
    EXPECT_FALSE(wrongKey);
}

TEST(Given_HostedConnectionRegistry, When_ConnectionIsReplaced_Then_PreviousConnectionCanComplete)
{
    tailgate::linux_frontend::HostedConnectionRegistry registry;
    bool previousClosed = false;
    const tailgate::crypto::Bytes32 nodePublicKey = tailgate::crypto::GeneratePrivateKey();
    registry.UpdateNetworkMap(NetworkMapFor(nodePublicKey));
    tailgate::linux_frontend::HostedConnectionRegistrationResult initial = registry.Register(
        "fake-profile",
        [&]
        {
            previousClosed = true;
        },
        HostedNodeId);

    tailgate::linux_frontend::HostedConnectionRegistrationResult replacement = registry.Register(
        "fake-profile",
        []
        {
        },
        HostedNodeId + 1);
    bool previousCompleted = false;
    if (replacement.Previous)
    {
        replacement.Previous->Close();
        registry.Unregister("fake-profile", replacement.Previous);
        previousCompleted = replacement.Previous->WaitForCompletion(std::chrono::seconds::zero());
    }

    EXPECT_EQ(replacement.Previous, initial.Current);
    EXPECT_TRUE(previousClosed);
    EXPECT_TRUE(previousCompleted);
    EXPECT_EQ(registry.PathForNode(HostedNodeId + 1), "tailgate(relay)");
}
