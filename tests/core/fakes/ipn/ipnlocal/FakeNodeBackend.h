#pragma once

#include <tailgate/ipn/ipnlocal/NodeBackend.h>

namespace tailgate::tests::fakes
{

class FakeNodeBackend final : public ipn::ipnlocal::NodeBackend
{
public:
    void UpdateNetwork(types::netmap::NetworkConfig network) override
    {
        Config = std::move(network);
    }

    ipn::ipnlocal::NodeEvents Wait(std::size_t, std::size_t, std::size_t) override
    {
        return {};
    }

    wgengine::ping::StartStatus StartPing(const wgengine::ping::Request& request) override
    {
        Requests.push_back(request);
        return PingStatus;
    }

    ipn::ipnlocal::DnsForward ForwardDns(const net::Endpoint&,
                                         std::vector<std::uint8_t>,
                                         const std::vector<std::string>&) override
    {
        return {};
    }

    std::optional<ipn::ipnlocal::DnsReply> CompleteDns(const net::Endpoint&,
                                                       std::vector<std::uint8_t>) override
    {
        return {};
    }

    const types::netmap::NetworkConfig& Network() const noexcept override
    {
        return Config;
    }

    const ipn::ipnlocal::NetworkPolicy& Policy() const noexcept override
    {
        return HostPolicy;
    }

    void SetPeerApiPort(std::optional<std::uint16_t>) noexcept override
    {
    }

    void UpdateStatus(Status&) const override
    {
    }

    void PublishEndpoints(const net::Endpoint&, std::optional<net::Endpoint>) override
    {
    }

    bool Ready() const noexcept override
    {
        return true;
    }

    void Shutdown() override
    {
    }

    types::netmap::NetworkConfig Config;
    ipn::ipnlocal::NetworkPolicy HostPolicy{""};
    wgengine::ping::StartStatus PingStatus = wgengine::ping::StartStatus::Ready;
    std::vector<wgengine::ping::Request> Requests;
};

} // namespace tailgate::tests::fakes
