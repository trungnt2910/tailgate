#pragma once

#include <tailgate/ipn/ipnlocal/DerpConnections.h>

namespace tailgate::linux_frontend
{

class DerpTransports final : public tailgate::ipn::ipnlocal::DerpTransportFactory
{
public:
    DerpTransports(tailgate::derp::ConnectionFactory& factory,
                   tailgate::derp::ConnectionOptions options);
    void SetNetworkInterface(const std::string& networkInterface) override;
    [[nodiscard]] std::unique_ptr<tailgate::derp::Connection> Create(int region,
                                                                     const std::string& host,
                                                                     bool preferred,
                                                                     std::size_t index,
                                                                     bool enabled) override;

private:
    tailgate::derp::ConnectionFactory& m_factory;
    tailgate::derp::ConnectionOptions m_options;
};

} // namespace tailgate::linux_frontend
