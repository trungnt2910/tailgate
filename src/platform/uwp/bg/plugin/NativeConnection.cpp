#include "NativeConnection.h"

#include <chrono>
#include <utility>

#include <tailgate/base/Logger.h>
#include <tailgate/ipn/ipnlocal/NodeBootstrap.h>
#include <tailgate/wgengine/magicsock/Bind.h>

#include "common/NetworkAdapter.h"
#include "common/UdpEndpointResolver.h"

namespace tailgate::uwp::bg
{
namespace
{

constexpr tailgate::base::EventToken NativeUdpToken{.Value = 3};
constexpr tailgate::base::EventToken NativeDeviceToken{.Value = 4};
constexpr std::uint64_t FirstNativeDerpToken = 5;
constexpr auto BindTimeout = std::chrono::seconds(10);

} // namespace

NativeConnection::NativeConnection(PluginInjector injector,
                                   std::string networkInterface,
                                   const tailgate::crypto::Bytes32& privateKey,
                                   const tailgate::crypto::Bytes32& publicKey)
    : m_injector(std::move(injector)),
      m_networkInterface(std::move(networkInterface)),
      m_events(m_injector->create<tailgate::base::EventLoop&>()),
      m_time(m_injector->create<tailgate::base::TimeProvider&>()),
      m_udp(m_injector->create<tailgate::wgengine::magicsock::Connection&>()),
      m_session(m_injector->create<tailgate::wgengine::Session&>()),
      m_device(m_injector->create<PacketDevice&>()),
      m_node(m_session,
             m_injector->create<tailgate::wgengine::Engine&>(),
             m_udp,
             m_injector->create<tailgate::ipn::ipnlocal::LocalServices&>(),
             m_injector->create<tailgate::ipn::ipnlocal::DnsForwarder&>(),
             m_injector->create<tailgate::wgengine::ping::Tracker&>(),
             m_time,
             *this),
      m_platformResolver(m_injector->create<tailgate::types::nettype::TcpSocketFactory&>()),
      m_resolver(m_platformResolver, m_events, m_time)
{
    m_derpOptions.NetworkInterface = m_networkInterface;
    m_derpOptions.PrivateKey = privateKey;
    m_derpOptions.PublicKey = publicKey;
}

tailgate::net::Endpoint NativeConnection::Open(std::stop_token cancellation)
{
    const auto endpoint =
        tailgate::wgengine::magicsock::Bind(m_udp,
                                            {.BindEndpoint = {},
                                             .NetworkInterface = m_networkInterface,
                                             .ReadinessToken = NativeUdpToken},
                                            m_events,
                                            m_time,
                                            BindTimeout,
                                            cancellation);
    return tailgate::net::Endpoint(NetworkAdapter(m_networkInterface).Ipv4Address(),
                                   endpoint.Port());
}

std::vector<tailgate::control::client::MapEndpoint>
NativeConnection::DiscoverEndpoints(const tailgate::types::netmap::NetworkConfig& network,
                                    const tailgate::net::Endpoint& local,
                                    std::stop_token cancellation)
{
    m_stunServer.reset();
    try
    {
        m_stunServer = m_bootstrapResolver.Resolve(network.StunHost().empty() ? network.DerpHost()
                                                                              : network.StunHost(),
                                                   network.StunPort(),
                                                   cancellation);
    }
    catch (...)
    {
        if (cancellation.stop_requested())
        {
            throw;
        }
        tailgate::base::Logger("uwp-native")
            .LogWarning("STUN lookup failed; retaining DERP fallback");
    }
    return tailgate::ipn::ipnlocal::NodeBootstrap::DiscoverEndpoints(
        m_session, local, m_stunServer);
}

void NativeConnection::Start(tailgate::types::netmap::NetworkConfig network,
                             tailgate::wgengine::SessionOptions options,
                             bool enableDerp)
{
    m_node.Start(std::move(network),
                 std::move(options),
                 {.Name = {}, .ReadinessToken = NativeDeviceToken},
                 {.BindEndpoint = {},
                  .NetworkInterface = m_networkInterface,
                  .ReadinessToken = NativeUdpToken},
                 m_stunServer,
                 enableDerp);
    if (!m_stunServer)
    {
        const auto& config = m_node.Network();
        m_resolver.Start(config.StunHost().empty() ? config.DerpHost() : config.StunHost(),
                         config.StunPort(),
                         m_networkInterface);
    }
}

tailgate::net::Endpoint NativeConnection::LocalEndpoint(const tailgate::net::Endpoint& bound) const
{
    return tailgate::net::Endpoint(NetworkAdapter(m_networkInterface).Ipv4Address(), bound.Port());
}

std::unique_ptr<tailgate::derp::Connection> NativeConnection::Create(
    int, const std::string& host, bool preferred, std::size_t index, bool enabled)
{
    auto options = m_derpOptions;
    options.Host = host;
    options.Preferred = preferred;
    options.Enabled = enabled;
    options.ReadinessToken.Value = FirstNativeDerpToken + index;
    return m_injector->create<tailgate::derp::ConnectionFactory&>().CreateConnection(
        std::move(options));
}

void NativeConnection::SuspendNetwork()
{
    m_resolver.Cancel();
    m_node.SuspendNetwork();
}

void NativeConnection::ChangeNetwork(std::string networkInterface)
{
    m_networkInterface = std::move(networkInterface);
    m_derpOptions.NetworkInterface = m_networkInterface;
    const auto& network = m_node.Network();
    m_resolver.Start(network.StunHost().empty() ? network.DerpHost() : network.StunHost(),
                     network.StunPort(),
                     m_networkInterface);
    // The shared switching owner has already replaced sockets; this wrapper refreshes platform DNS.
}

void NativeConnection::PollResolution()
{
    if (const auto resolved = m_resolver.Poll())
    {
        m_node.SetStunServer(resolved);
    }
}

tailgate::wgengine::Session& NativeConnection::Session() noexcept
{
    return m_session;
}

tailgate::ipn::ipnlocal::NativeNode& NativeConnection::Node() noexcept
{
    return m_node;
}

PacketDevice& NativeConnection::Device() noexcept
{
    return m_device;
}

void NativeConnection::SetNetworkInterface(const std::string& value)
{
    m_derpOptions.NetworkInterface = value;
}

} // namespace tailgate::uwp::bg
