#include "DerpTransports.h"

#include <utility>

#include "DataplaneEvents.h"

namespace tailgate::linux_frontend
{

DerpTransports::DerpTransports(tailgate::derp::ConnectionFactory& factory,
                               tailgate::derp::ConnectionOptions options)
    : m_factory(factory), m_options(std::move(options))
{
}

std::unique_ptr<tailgate::derp::Connection> DerpTransports::Create(
    int, const std::string& host, bool preferred, std::size_t index, bool enabled)
{
    auto options = m_options;
    options.Host = host;
    options.Preferred = preferred;
    options.Enabled = enabled;
    options.ReadinessToken =
        DataplaneEvent(DataplaneEvent::Kind::Derp, static_cast<std::uint32_t>(index)).Token();
    return m_factory.CreateConnection(std::move(options));
}

void DerpTransports::SetNetworkInterface(const std::string& value)
{
    m_options.NetworkInterface = value;
}

} // namespace tailgate::linux_frontend
