#include "HostedConnectionRegistry.h"

#include <algorithm>
#include <utility>

namespace tailgate::linux_frontend
{

HostedConnectionRegistration::HostedConnectionRegistration(std::function<void()> closeConnection,
                                                           std::uint64_t nodeId)
    : m_closeConnection(std::move(closeConnection)), m_nodeId(nodeId)
{
}

HostedConnectionRegistration::~HostedConnectionRegistration()
{
    Complete();
}

void HostedConnectionRegistration::Complete()
{
    {
        std::lock_guard lock(m_completionMutex);
        m_completed = true;
    }
    m_completionChanged.notify_all();
}

void HostedConnectionRegistration::Close()
{
    m_closeConnection();
}

bool HostedConnectionRegistration::WaitForCompletion(std::chrono::seconds timeout)
{
    std::unique_lock lock(m_completionMutex);
    return m_completionChanged.wait_for(lock,
                                        timeout,
                                        [&]()
                                        {
                                            return m_completed;
                                        });
}

std::uint64_t HostedConnectionRegistration::NodeId() const noexcept
{
    return m_nodeId;
}

void HostedConnectionRegistry::UpdateNetworkMap(
    const tailgate::types::netmap::NetworkConfig& config)
{
    std::vector<VisibleNode> visible;
    visible.reserve(config.Peers().size());
    for (const tailgate::types::netmap::PeerConfig& peer : config.Peers())
    {
        if (peer.NodeId() != 0)
        {
            visible.push_back(VisibleNode{.NodeId = peer.NodeId(), .Key = peer.Key()});
        }
    }
    {
        std::lock_guard lock(m_mutex);
        m_tailnet = config.Domain();
        const std::size_t dot = config.SelfName().find('.');
        m_relayHostName =
            dot == std::string::npos ? config.SelfName() : config.SelfName().substr(0, dot);
        m_visibleNodes = std::move(visible);
        ++m_mapGeneration;
    }
    m_mapChanged.notify_all();
}

std::optional<std::string> HostedConnectionRegistry::PathForNode(std::uint64_t nodeId) const
{
    if (nodeId == 0)
    {
        return std::nullopt;
    }
    std::lock_guard lock(m_mutex);
    const bool active =
        std::any_of(m_connections.begin(),
                    m_connections.end(),
                    [&](const auto& entry)
                    {
                        const std::shared_ptr<HostedConnectionRegistration> registration =
                            entry.second.lock();
                        return registration && registration->NodeId() == nodeId;
                    });
    return active ? std::optional<std::string>("tailgate(" + m_relayHostName + ")") : std::nullopt;
}

bool HostedConnectionRegistry::IsNodeVisible(const std::string& tailnet,
                                             std::uint64_t nodeId,
                                             const tailgate::crypto::Bytes32& nodePublicKey) const
{
    std::lock_guard lock(m_mutex);
    return IsNodeVisibleLocked(tailnet, nodeId, nodePublicKey);
}

HostedNodeVisibility
HostedConnectionRegistry::WaitForNodeVisibility(const std::string& tailnet,
                                                std::uint64_t nodeId,
                                                const tailgate::crypto::Bytes32& nodePublicKey,
                                                std::chrono::seconds timeout)
{
    std::unique_lock lock(m_mutex);
    if (IsNodeVisibleLocked(tailnet, nodeId, nodePublicKey))
    {
        return HostedNodeVisibility::Visible;
    }
    const std::uint64_t generation = m_mapGeneration;
    const bool found =
        m_mapChanged.wait_for(lock,
                              timeout,
                              [&]()
                              {
                                  return IsNodeVisibleLocked(tailnet, nodeId, nodePublicKey);
                              });
    if (found)
    {
        return HostedNodeVisibility::Visible;
    }
    return m_mapGeneration == generation ? HostedNodeVisibility::TimedOut
                                         : HostedNodeVisibility::MissingAfterUpdate;
}

HostedConnectionRegistrationResult HostedConnectionRegistry::Register(
    std::string profileKey, std::function<void()> closeConnection, std::uint64_t nodeId)
{
    auto current =
        std::make_shared<HostedConnectionRegistration>(std::move(closeConnection), nodeId);
    std::lock_guard lock(m_mutex);
    std::shared_ptr<HostedConnectionRegistration> previous = m_connections[profileKey].lock();
    m_connections[std::move(profileKey)] = current;
    return HostedConnectionRegistrationResult{
        .Current = std::move(current),
        .Previous = std::move(previous),
    };
}

void HostedConnectionRegistry::Unregister(
    const std::string& profileKey,
    const std::shared_ptr<HostedConnectionRegistration>& registration)
{
    std::lock_guard lock(m_mutex);
    const auto found = m_connections.find(profileKey);
    if (found != m_connections.end() && found->second.lock() == registration)
    {
        m_connections.erase(found);
    }
    registration->Complete();
}

bool HostedConnectionRegistry::IsNodeVisibleLocked(
    const std::string& tailnet,
    std::uint64_t nodeId,
    const tailgate::crypto::Bytes32& nodePublicKey) const
{
    const std::string key =
        "nodekey:" + tailgate::crypto::BytesToHex(nodePublicKey.data(), nodePublicKey.size());
    return m_tailnet == tailnet && std::any_of(m_visibleNodes.begin(),
                                               m_visibleNodes.end(),
                                               [&](const VisibleNode& node)
                                               {
                                                   return node.NodeId == nodeId && node.Key == key;
                                               });
}

} // namespace tailgate::linux_frontend
