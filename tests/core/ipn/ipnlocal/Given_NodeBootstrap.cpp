#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/NodeBootstrap.h>
#include <tailgate/ipn/ipnlocal/NodeError.h>

#include "control/client/impl/ConnectionImpl.h"

#include "fakes/control/client/FakeSession.h"
#include "fakes/crypto/FakeCertificate.h"
#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/net/http/FakeClient.h"

namespace
{

class Given_NodeBootstrap : public testing::Test, public tailgate::ipn::ipnlocal::BootstrapPlatform
{
protected:
    Given_NodeBootstrap()
        : State(std::make_shared<tailgate::tests::fakes::control::client::SessionState>()),
          Factory(State),
          Control({}, Factory, Sockets, Time, Events)
    {
        tailgate::tests::fakes::InstallFakeNetworkBindings(Injector);
        Network.SelfAddress("100.64.0.1");
        Network.DerpRegion(1);
        Network.DerpHost("derp.example.com");
        State->Registration.Network = Network;
        Bootstrap = std::make_unique<tailgate::ipn::ipnlocal::NodeBootstrap>(
            Control, Injector.create<tailgate::wgengine::Session&>(), Http, Crypto, *this);
    }

    tailgate::net::Endpoint ResolveUdp(const std::string&, std::uint16_t) override
    {
        throw tailgate::net::EndpointParseError();
    }

    std::optional<tailgate::serve::acme::CertificateState> ReadCertificate() override
    {
        return Cached;
    }

    void WriteCertificate(const tailgate::serve::acme::CertificateState& state) override
    {
        Cached = state;
        ++CertificateWrites;
    }

    void Registered(const tailgate::types::netmap::NetworkConfig&) override
    {
        ++Registrations;
    }

    tailgate::di::Injector Injector;
    std::shared_ptr<tailgate::tests::fakes::control::client::SessionState> State;
    tailgate::tests::fakes::control::client::FakeSessionFactory Factory;
    tailgate::tests::fakes::FakeTcpSocketFactory Sockets;
    tailgate::tests::fakes::FakeTimeProvider Time;
    tailgate::tests::fakes::FakeEventLoop Events;
    tailgate::control::client::impl::ConnectionImpl Control;
    tailgate::tests::fakes::net::http::FakeClient Http;
    tailgate::tests::fakes::FakeCertificate Crypto;
    tailgate::types::netmap::NetworkConfig Network;
    std::unique_ptr<tailgate::ipn::ipnlocal::NodeBootstrap> Bootstrap;
    const tailgate::net::Endpoint Local = tailgate::net::Endpoint::Parse("192.0.2.1:12345");
    int Registrations = 0;
    int CertificateWrites = 0;
    std::optional<tailgate::serve::acme::CertificateState> Cached;
};

} // namespace

TEST_F(Given_NodeBootstrap, When_StunDiscoveryFails_Then_ControlStillStartsWithHomeDerp)
{
    State->Registration.NetworkMapStreaming = true;

    const auto result = Bootstrap->Start("", {}, Local, {}, "");

    EXPECT_EQ(result.DerpRegion, 1);
    EXPECT_EQ(result.DerpHost, "derp.example.com");
    EXPECT_EQ(Registrations, 1);
    EXPECT_TRUE(State->NonBlocking);
    EXPECT_LT(std::ranges::find(State->Operations, "update-host-info"),
              std::ranges::find(State->Operations, "enable-nonblocking"));
    EXPECT_EQ(std::ranges::find(State->Operations, "set-preferred-derp"), State->Operations.end());
}

TEST_F(Given_NodeBootstrap, When_ExitNodeIsSelected_Then_ItsDerpBecomesHome)
{
    tailgate::types::netmap::PeerConfig peer;
    peer.Name("exit.example.ts.net");
    peer.Address("100.64.0.2");
    peer.ExitNodeOption(true);
    peer.Online(true);
    peer.DerpRegion(2);
    peer.DerpHost("exit-derp.example.com");
    Network.Peers({peer});
    State->Registration.Network = Network;

    const auto result = Bootstrap->Start("", {}, Local, {}, "exit.example.ts.net");

    EXPECT_EQ(result.DerpRegion, 2);
    EXPECT_EQ(result.DerpHost, "exit-derp.example.com");
    EXPECT_NE(std::ranges::find(State->Operations, "set-preferred-derp"), State->Operations.end());
}

TEST_F(Given_NodeBootstrap, When_RegistrationHasNoMap_Then_StreamingDoesNotStart)
{
    State->Registration.Network.reset();
    const auto start = [&]()
    {
        (void)Bootstrap->Start("", {}, Local, {}, "");
    };

    EXPECT_THROW(start(), tailgate::ipn::ipnlocal::NodeError);
    EXPECT_EQ(Registrations, 0);
    EXPECT_FALSE(State->NonBlocking);
}

TEST_F(Given_NodeBootstrap, When_SelectedExitNodeIsMissing_Then_BootstrapFails)
{
    const auto start = [&]()
    {
        (void)Bootstrap->Start("", {}, Local, {}, "missing.example.ts.net");
    };

    EXPECT_THROW(start(), tailgate::ipn::ipnlocal::NodeError);
    EXPECT_FALSE(State->NonBlocking);
}

TEST_F(Given_NodeBootstrap, When_FunnelCertificateIsReusable_Then_IssuanceAndStorageAreSkipped)
{
    Network.SelfName("node.example.ts.net.");
    Network.CertDomains({"node.example.ts.net"});
    Network.Capabilities({"https", "funnel", "https://tailscale.com/cap/funnel-ports?ports=443"});
    State->Registration.Network = Network;
    Cached = tailgate::serve::acme::CertificateState{.Domain = "node.example.ts.net",
                                                     .AccountPrivateKey = "example-account-key",
                                                     .CertificatePem = "example-certificate",
                                                     .PrivateKeyPem = "example-private-key"};
    const auto funnel = tailgate::serve::TlsTerminatedTcpFunnel(443, 8080);

    const auto result = Bootstrap->Start("", {}, Local, funnel, "");

    EXPECT_EQ(result.CertificatePem, "example-certificate");
    EXPECT_EQ(result.PrivateKeyPem, "example-private-key");
    EXPECT_EQ(CertificateWrites, 0);
    EXPECT_TRUE(Http.Requests.empty());
}

TEST_F(Given_NodeBootstrap, When_FunnelCertificateDomainIsUnauthorized_Then_NoCertificateIsIssued)
{
    Network.SelfName("node.example.ts.net");
    Network.Capabilities({"https", "funnel", "https://tailscale.com/cap/funnel-ports?ports=443"});
    State->Registration.Network = Network;
    const auto funnel = tailgate::serve::TlsTerminatedTcpFunnel(443, 8080);
    const auto start = [&]()
    {
        (void)Bootstrap->Start("", {}, Local, funnel, "");
    };

    EXPECT_THROW(start(), tailgate::ipn::ipnlocal::NodeError);
    EXPECT_EQ(CertificateWrites, 0);
    EXPECT_TRUE(Http.Requests.empty());
    EXPECT_FALSE(State->NonBlocking);
}
