#include "tailgate/ipn/ipnlocal/SwitchingNode.h"

#include <algorithm>
#include <iterator>
#include <utility>

#include <tailgate/ipn/ipnlocal/NodeError.h>

namespace tailgate::ipn::ipnlocal
{

SwitchingNode::SwitchingNode(NativeNode& native,
                             HostedNode& hosted,
                             hosted::Recovery& preparation,
                             base::TimeProvider& time,
                             NodeMode initial,
                             wgengine::tstun::DeviceOptions device,
                             std::string exitNode)
    : m_native(native),
      m_hosted(hosted),
      m_preparation(preparation),
      m_transition(time, initial),
      m_selected(initial),
      m_device(std::move(device)),
      m_exitNode(std::move(exitNode))
{
    if (initial == NodeMode::Hosted)
    {
        m_hosted.Select();
    }
    else
    {
        m_native.Select();
    }
}

bool SwitchingNode::RequestMode(NodeMode desired, std::optional<hosted::ConnectionOptions> relay)
{
    if (desired == m_selected && m_transition.Status().Phase == TransitionPhase::Idle)
    {
        return true;
    }
    if (desired == NodeMode::Hosted && !relay)
    {
        throw NodeError(NodeFailure::InvalidTransportOptions);
    }
    if (m_transition.Status().Phase != TransitionPhase::Idle &&
        m_transition.Status().Phase != TransitionPhase::Failed)
    {
        return false;
    }
    m_relayOptions = std::move(relay);
    if (m_relayOptions)
    {
        m_relayOptions->Client.Network = Network();
        m_relayOptions->Client.ExitNode = m_exitNode;
        const auto name =
            m_relayOptions->Socket.TlsServerName.value_or(m_relayOptions->Socket.ConnectAddress);
        m_relayName = name.substr(0, name.find('.'));
    }
    auto regions = Regions();
    const auto revision = desired == NodeMode::Native ? m_hosted.MapRevision() : 1;
    const auto accepted = m_transition.Begin(desired, revision, std::move(regions), true);
    if (desired == NodeMode::Native)
    {
        m_transition.MapApplied(m_appliedMap);
    }
    else
    {
        m_appliedMap = 0;
    }
    ApplyActions();
    return accepted;
}

std::vector<std::uint16_t> SwitchingNode::Regions() const
{
    std::vector<std::uint16_t> regions{static_cast<std::uint16_t>(Network().DerpRegion())};
    for (const auto& peer : Network().Peers())
    {
        if (peer.DerpRegion() > 0)
        {
            regions.push_back(static_cast<std::uint16_t>(peer.DerpRegion()));
        }
    }
    return regions;
}

void SwitchingNode::ReconcileMap()
{
    if (m_hosted.HasTransport())
    {
        m_transition.MapChanged(m_hosted.MapRevision(), Regions());
        m_transition.MapApplied(m_appliedMap);
    }
}

bool SwitchingNode::TransportReady() const
{
    return m_selected == NodeMode::Native ? m_native.Connected() : m_hosted.Ready();
}

void SwitchingNode::SetStunServer(std::optional<net::Endpoint> server)
{
    m_native.SetStunServer(server);
}

void SwitchingNode::ChangeNetwork(std::optional<std::string> networkInterface)
{
    m_preparation.Cancel();
    m_preparedRelay.reset();
    m_native.SetDerpEnabled(false);
    m_native.SuspendNetwork();
    m_hosted.StopRecovery();
    m_hosted.RetireTransport();
    m_transition.Abort(TransitionFailure::Cancelled);
    if (!networkInterface)
    {
        return;
    }
    m_native.ChangeNetwork(*networkInterface, std::nullopt);
    m_native.SetDerpEnabled(m_selected == NodeMode::Native);
    if (m_selected == NodeMode::Hosted)
    {
        m_hosted.ChangeNetwork(*networkInterface);
    }
}

void SwitchingNode::CancelTransition(TransitionFailure reason)
{
    m_preparation.Cancel();
    m_preparedRelay.reset();
    m_transition.Cancel(reason);
    ApplyActions();
}

const TransitionStatus& SwitchingNode::Transition() const noexcept
{
    return m_transition.Status();
}

NodeBackend& SwitchingNode::Active() const noexcept
{
    return m_selected == NodeMode::Native ? static_cast<NodeBackend&>(m_native)
                                          : static_cast<NodeBackend&>(m_hosted);
}

void SwitchingNode::ApplyActions()
{
    for (auto& action : m_transition.TakeActions())
    {
        if (action.Generation != m_transition.Status().Generation)
        {
            continue;
        }
        using Action = TransitionActionKind;
        switch (action.Kind)
        {
        case Action::PrepareNative:
            m_hosted.StopRecovery();
            m_native.SetDerpEnabled(false);
            m_native.PrepareTransport();
            m_preparationGeneration = action.Generation;
            break;
        case Action::PrepareHosted:
            m_preparation.Configure(*m_relayOptions);
            m_preparation.Failed();
            m_preparationGeneration = action.Generation;
            break;
        case Action::SuspendNative:
            m_native.SetDerpEnabled(false);
            break;
        case Action::ActivateNative:
            m_native.SetDerpEnabled(true);
            if (m_transition.Status().Phase == TransitionPhase::Failed)
            {
                m_native.Select();
                m_selected = NodeMode::Native;
            }
            break;
        case Action::ActivateHosted:
            if (!m_preparedRelay)
            {
                m_transition.Cancel(TransitionFailure::PreparationFailed);
                break;
            }
            m_preparedRelay->Configuration.Network = m_native.Network();
            m_hosted.Start(std::move(*m_preparedRelay), m_device, m_exitNode, m_relayName);
            m_preparedRelay.reset();
            break;
        case Action::SelectNative:
            m_native.Select();
            m_selected = NodeMode::Native;
            break;
        case Action::SelectHosted:
            m_hosted.Select();
            m_selected = NodeMode::Hosted;
            break;
        case Action::RetireNative:
            m_native.SetDerpEnabled(false);
            m_native.SuspendNetwork();
            if (m_selected == NodeMode::Hosted)
            {
                m_hosted.ResumeRecovery();
            }
            break;
        case Action::RetireHosted:
            m_preparation.Cancel();
            m_preparedRelay.reset();
            m_hosted.StopRecovery();
            m_hosted.RetireTransport();
            break;
        case Action::RecoverHosted:
            m_hosted.ResumeRecovery();
            m_hosted.Select();
            m_selected = NodeMode::Hosted;
            break;
        case Action::Delegation:
            try
            {
                m_hosted.RequestDelegation(*action.Delegation);
            }
            catch (const std::system_error&)
            {
                m_transition.RelayFailed();
            }
            break;
        }
    }
}

void SwitchingNode::Observe(const NodeEvents& result)
{
    if (result.AppliedMapRevision)
    {
        m_appliedMap = *result.AppliedMapRevision;
        m_transition.MapApplied(m_appliedMap);
    }
    for (const auto& reply : result.DelegationReplies)
    {
        m_transition.Reply(reply);
    }
    if (result.TransportFailure)
    {
        m_transition.RelayFailed();
    }
}

void SwitchingNode::Merge(NodeEvents& destination, NodeEvents source)
{
    destination.Received.insert(destination.Received.end(),
                                std::make_move_iterator(source.Received.begin()),
                                std::make_move_iterator(source.Received.end()));
    destination.DelegationReplies.insert(destination.DelegationReplies.end(),
                                         source.DelegationReplies.begin(),
                                         source.DelegationReplies.end());
    if (source.AppliedMapRevision)
    {
        destination.AppliedMapRevision = source.AppliedMapRevision;
    }
    if (source.TransportFailure)
    {
        destination.TransportFailure = source.TransportFailure;
    }
    if (source.Endpoints)
    {
        destination.Endpoints = source.Endpoints;
    }
    destination.NetworkChanged |= source.NetworkChanged;
    destination.DataPathReady |= source.DataPathReady;
}

void SwitchingNode::Advance(std::size_t maximumPackets, NodeEvents& result)
{
    ApplyActions();
    const auto status = m_transition.Status();
    if (status.Phase == TransitionPhase::Preparing && status.Desired == NodeMode::Hosted)
    {
        if (auto candidate = m_preparation.Poll())
        {
            m_preparedRelay = std::move(candidate);
            m_transition.Prepared(m_preparationGeneration, true);
        }
    }
    if (m_selected == NodeMode::Hosted)
    {
        m_native.PollTransport();
        if (auto endpoints = m_native.TakeEndpoints())
        {
            result.Endpoints = endpoints;
        }
    }
    if (status.Phase == TransitionPhase::Preparing && status.Desired == NodeMode::Native &&
        m_native.TransportPrepared())
    {
        m_transition.Prepared(m_preparationGeneration, true);
    }
    if (m_selected == NodeMode::Native && m_hosted.HasTransport())
    {
        auto passive = m_hosted.PollTransport(maximumPackets);
        Observe(passive);
        if (passive.NetworkChanged)
        {
            m_native.UpdateNetwork(m_hosted.Network());
            ReconcileMap();
        }
        Merge(result, std::move(passive));
    }
    if (m_native.OwnershipReady())
    {
        m_transition.NativeReady(m_transition.Status().Generation);
    }
    m_transition.Poll();
    ApplyActions();
}

NodeEvents SwitchingNode::Wait(std::size_t maximumEvents,
                               std::size_t maximumPackets,
                               std::size_t maximumPacketSize)
{
    NodeEvents result;
    Advance(maximumPackets, result);
    auto completed = Active().Wait(maximumEvents, maximumPackets, maximumPacketSize);
    Observe(completed);
    if (completed.NetworkChanged)
    {
        if (m_selected == NodeMode::Hosted)
        {
            m_native.UpdateNetwork(m_hosted.Network());
        }
        else if (m_hosted.HasTransport())
        {
            m_hosted.UpdateNetwork(m_native.Network());
        }
        ReconcileMap();
    }
    result.Transport = std::move(completed.Transport);
    Merge(result, std::move(completed));
    Advance(maximumPackets, result);
    return result;
}

void SwitchingNode::UpdateNetwork(types::netmap::NetworkConfig network)
{
    m_native.UpdateNetwork(network);
    if (m_hosted.HasTransport())
    {
        m_hosted.UpdateNetwork(std::move(network));
    }
    ReconcileMap();
    ApplyActions();
}

wgengine::ping::StartStatus SwitchingNode::StartPing(const wgengine::ping::Request& request)
{
    auto options = request;
    if (m_selected == NodeMode::Native)
    {
        options.Relay.clear();
    }
    return Active().StartPing(options);
}

DnsForward SwitchingNode::ForwardDns(const net::Endpoint& client,
                                     std::vector<std::uint8_t> payload,
                                     const std::vector<std::string>& resolvers)
{
    return Active().ForwardDns(client, std::move(payload), resolvers);
}

std::optional<DnsReply> SwitchingNode::CompleteDns(const net::Endpoint& source,
                                                   std::vector<std::uint8_t> payload)
{
    return Active().CompleteDns(source, std::move(payload));
}

const types::netmap::NetworkConfig& SwitchingNode::Network() const noexcept
{
    return Active().Network();
}

const NetworkPolicy& SwitchingNode::Policy() const noexcept
{
    return Active().Policy();
}

void SwitchingNode::SetPeerApiPort(std::optional<std::uint16_t> port) noexcept
{
    m_native.SetPeerApiPort(port);
    m_hosted.SetPeerApiPort(port);
}

void SwitchingNode::UpdateStatus(Status& status) const
{
    Active().UpdateStatus(status);
}

void SwitchingNode::PublishEndpoints(const net::Endpoint& local,
                                     std::optional<net::Endpoint> endpoint)
{
    m_native.PublishEndpoints(local, endpoint);
}

bool SwitchingNode::Ready() const noexcept
{
    return Active().Ready();
}

void SwitchingNode::Shutdown()
{
    m_preparation.Cancel();
    m_hosted.StopRecovery();
    m_native.Shutdown();
    if (m_hosted.HasTransport())
    {
        m_hosted.Shutdown();
    }
}

} // namespace tailgate::ipn::ipnlocal
