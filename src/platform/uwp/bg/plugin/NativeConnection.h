#pragma once

#include <mutex>
#include <stop_token>
#include <thread>

#include <tailgate/ipn/ipnlocal/NativeNode.h>
#include <tailgate/ipn/ipnlocal/UnderlayResolver.h>

#include "common/UdpEndpointResolver.h"
#include "common/UnderlayResolver.h"

#include "bg/DI.h"

namespace tailgate::uwp::bg
{

class NativeConnection final : private tailgate::ipn::ipnlocal::DerpTransportFactory
{
public:
    NativeConnection(PluginInjector injector,
                     std::string networkInterface,
                     const tailgate::crypto::Bytes32& privateKey,
                     const tailgate::crypto::Bytes32& publicKey);
    [[nodiscard]] tailgate::net::Endpoint Open(std::stop_token cancellation);
    [[nodiscard]] std::vector<tailgate::control::client::MapEndpoint>
    DiscoverEndpoints(const tailgate::types::netmap::NetworkConfig& network,
                      const tailgate::net::Endpoint& local,
                      std::stop_token cancellation);
    void Start(tailgate::types::netmap::NetworkConfig network,
               tailgate::wgengine::SessionOptions options,
               bool enableDerp = true);
    [[nodiscard]] tailgate::net::Endpoint LocalEndpoint(const tailgate::net::Endpoint& bound) const;
    void ChangeNetwork(std::string networkInterface);
    void SuspendNetwork();
    void PollResolution();
    [[nodiscard]] tailgate::wgengine::Session& Session() noexcept;
    [[nodiscard]] tailgate::ipn::ipnlocal::NativeNode& Node() noexcept;
    [[nodiscard]] PacketDevice& Device() noexcept;

private:
    void SetNetworkInterface(const std::string& networkInterface) override;
    [[nodiscard]] std::unique_ptr<tailgate::derp::Connection> Create(int region,
                                                                     const std::string& host,
                                                                     bool preferred,
                                                                     std::size_t index,
                                                                     bool enabled) override;

    PluginInjector m_injector;
    std::string m_networkInterface;
    std::optional<tailgate::net::Endpoint> m_stunServer;
    tailgate::derp::ConnectionOptions m_derpOptions;
    tailgate::base::EventLoop& m_events;
    tailgate::base::TimeProvider& m_time;
    tailgate::wgengine::magicsock::Connection& m_udp;
    tailgate::wgengine::Session& m_session;
    PacketDevice& m_device;
    tailgate::ipn::ipnlocal::NativeNode m_node;
    UdpEndpointResolver m_bootstrapResolver;
    tailgate::uwp::UnderlayResolver m_platformResolver;
    tailgate::ipn::ipnlocal::UnderlayResolver m_resolver;
};

} // namespace tailgate::uwp::bg
