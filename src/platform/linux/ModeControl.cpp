#include "ModeControl.h"

#include <format>

#include <tailgate/hosted/RelayEndpoint.h>

namespace tailgate::linux_frontend
{

ModeControl::ModeControl(ipn::ipnlocal::SwitchingNode& node, hosted::ConnectionOptions options)
    : m_node(node), m_options(std::move(options)), m_settings(ReadSettings())
{
}

bool ModeControl::Reload()
{
    const auto next = ReadSettings();
    if (!next || !m_settings || next->Hostname != m_settings->Hostname ||
        next->ExitNode != m_settings->ExitNode || next->AcceptDns != m_settings->AcceptDns ||
        next->FunnelPort != m_settings->FunnelPort ||
        next->FunnelLocalPort != m_settings->FunnelLocalPort ||
        next->ExposePort != m_settings->ExposePort ||
        (!next->TailgateUrl.empty() && !m_settings->TailgateUrl.empty() &&
         next->TailgateUrl != m_settings->TailgateUrl))
    {
        return false;
    }
    auto relay = m_options;
    if (!next->TailgateUrl.empty())
    {
        const auto endpoint = hosted::RelayEndpoint::Parse(next->TailgateUrl);
        relay.Socket.ConnectAddress = endpoint.Host;
        relay.Socket.Service = endpoint.Port;
        relay.Socket.TlsServerName = endpoint.Host;
        relay.HttpHost = std::format("{}:{}", endpoint.Host, endpoint.Port);
    }
    const auto desired = next->TailgateUrl.empty() ? ipn::ipnlocal::NodeMode::Native
                                                   : ipn::ipnlocal::NodeMode::Hosted;
    if (!m_node.RequestMode(desired, std::move(relay)))
    {
        return false;
    }
    m_settings = next;
    m_reported.reset();
    return true;
}

bool ModeControl::UpdateStatus(DaemonStatus& status)
{
    const auto current = m_node.Transition();
    if (m_reported && *m_reported == current)
    {
        return false;
    }
    m_reported = current;
    status.DesiredMode = current.Desired == ipn::ipnlocal::NodeMode::Native ? "native" : "hosted";
    status.EffectiveMode =
        current.Effective == ipn::ipnlocal::NodeMode::Native ? "native" : "hosted";
    status.ModeTransition = static_cast<unsigned>(current.Phase);
    status.ModeFailure = static_cast<unsigned>(current.Failure);
    if (current.Phase == ipn::ipnlocal::TransitionPhase::Idle ||
        current.Phase == ipn::ipnlocal::TransitionPhase::Failed)
    {
        if (m_settings)
        {
            status.ConfigurationRevision = m_settings->Revision;
        }
        status.Error = current.Phase == ipn::ipnlocal::TransitionPhase::Failed
                           ? "transport mode change failed; retained node state"
                           : "";
    }
    return true;
}

void ModeControl::ChangeNetwork(std::optional<std::string> networkInterface)
{
    if (networkInterface)
    {
        m_options.Socket.NetworkInterface = *networkInterface;
    }
    m_node.ChangeNetwork(std::move(networkInterface));
}

void ModeControl::SetStunServer(std::optional<net::Endpoint> endpoint)
{
    m_node.SetStunServer(endpoint);
}

bool ModeControl::TransportReady() const
{
    return m_node.TransportReady();
}

} // namespace tailgate::linux_frontend
