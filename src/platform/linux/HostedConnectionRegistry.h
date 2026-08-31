#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::linux_frontend
{

class HostedConnectionRegistration final
{
public:
    HostedConnectionRegistration(std::function<void()> closeConnection, std::uint64_t nodeId);
    ~HostedConnectionRegistration();

    HostedConnectionRegistration(const HostedConnectionRegistration&) = delete;
    HostedConnectionRegistration& operator=(const HostedConnectionRegistration&) = delete;

    void Close();
    [[nodiscard]] bool WaitForCompletion(std::chrono::seconds timeout);
    [[nodiscard]] std::uint64_t NodeId() const noexcept;

private:
    friend class HostedConnectionRegistry;

    void Complete();

    std::function<void()> m_closeConnection;
    std::uint64_t m_nodeId = 0;
    std::mutex m_completionMutex;
    std::condition_variable m_completionChanged;
    bool m_completed = false;
};

enum class HostedNodeVisibility
{
    Visible,
    MissingAfterUpdate,
    TimedOut,
};

struct HostedConnectionRegistrationResult
{
    std::shared_ptr<HostedConnectionRegistration> Current;
    std::shared_ptr<HostedConnectionRegistration> Previous;
};

class HostedConnectionRegistry final
{
public:
    void UpdateNetworkMap(const tailgate::types::netmap::NetworkConfig& config);
    [[nodiscard]] std::optional<std::string> PathForNode(std::uint64_t nodeId) const;
    [[nodiscard]] bool IsNodeVisible(const std::string& tailnet,
                                     std::uint64_t nodeId,
                                     const tailgate::crypto::Bytes32& nodePublicKey) const;
    [[nodiscard]] HostedNodeVisibility
    WaitForNodeVisibility(const std::string& tailnet,
                          std::uint64_t nodeId,
                          const tailgate::crypto::Bytes32& nodePublicKey,
                          std::chrono::seconds timeout);
    [[nodiscard]] HostedConnectionRegistrationResult
    Register(std::string profileKey, std::function<void()> closeConnection, std::uint64_t nodeId);
    void Unregister(const std::string& profileKey,
                    const std::shared_ptr<HostedConnectionRegistration>& registration);

private:
    struct VisibleNode
    {
        std::uint64_t NodeId = 0;
        std::string Key;
    };

    [[nodiscard]] bool IsNodeVisibleLocked(const std::string& tailnet,
                                           std::uint64_t nodeId,
                                           const tailgate::crypto::Bytes32& nodePublicKey) const;

    mutable std::mutex m_mutex;
    std::condition_variable m_mapChanged;
    std::map<std::string, std::weak_ptr<HostedConnectionRegistration>> m_connections;
    std::vector<VisibleNode> m_visibleNodes;
    std::string m_tailnet;
    std::string m_relayHostName;
    std::uint64_t m_mapGeneration = 0;
};

} // namespace tailgate::linux_frontend
