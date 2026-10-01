#pragma once

#include <string>
#include <vector>

#include <tailgate/hosted/DerpRouteTable.h>
#include <tailgate/wgengine/Session.h>

namespace tailgate::ipn::ipnlocal
{

struct DerpRuntime
{
    int Region = 0;
    std::string Host;
    wgengine::DerpConnectionId Connection = 0;
    hosted::DerpRoute Route;
};

class DerpTransportFactory
{
public:
    virtual ~DerpTransportFactory() = default;
    virtual void SetNetworkInterface(const std::string& networkInterface) = 0;
    [[nodiscard]] virtual std::unique_ptr<derp::Connection> Create(
        int region, const std::string& host, bool preferred, std::size_t index, bool enabled) = 0;
};

// The factory owns transport and readiness registration; region selection and ingress
// route identity belong to the node and are shared by native and delegated sessions.
class DerpConnections final
{
public:
    DerpConnections(wgengine::Session& session, DerpTransportFactory& factory);
    std::size_t Ensure(int region, const std::string& host, bool preferred);
    void ApplyNetworkMap(const types::netmap::NetworkConfig& config);
    void ChangeNetwork(const std::string& networkInterface);
    void SetEnabled(bool enabled);
    [[nodiscard]] derp::Connection& ForRegion(int region);
    [[nodiscard]] derp::Connection* ForRoute(const hosted::DerpRoute& route);
    [[nodiscard]] const std::vector<DerpRuntime>& Entries() const noexcept;

private:
    wgengine::Session& m_session;
    DerpTransportFactory& m_factory;
    hosted::DerpRouteTable m_routes;
    std::vector<DerpRuntime> m_entries;
    bool m_enabled = true;
};

} // namespace tailgate::ipn::ipnlocal
