#pragma once

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stop_token>
#include <thread>

#include <tailgate/base/Logger.h>
#include <tailgate/control/client/Session.h>

#include "manager/ControlPlaneManager.h"

namespace tailgate::uwp
{

class TcpSocketFactory;

}

namespace tailgate::uwp::bg::manager
{

class ControlPlaneManagerImpl final : public ControlPlaneManager
{
public:
    ControlPlaneManagerImpl(SessionManager& sessionManager,
                            tailgate::control::client::SessionFactory& controlSessionFactory,
                            TcpSocketFactory& socketFactory);
    ~ControlPlaneManagerImpl() override;

    void Start(SessionGeneration generation, const std::string& networkInterface) override;
    void LoadIdentity(bool registered) override;
    [[nodiscard]] tailgate::control::client::RegistrationResult
    Connect(const std::string& authKey) override;
    void PublishEndpoints(std::vector<tailgate::control::client::MapEndpoint> endpoints) override;
    void ChangeNetwork(const std::string& networkInterface) override;
    void StartMaintenance(NetworkMapHandler networkMapHandler) override;
    void StopMaintenance() override;
    void RequestStop() override;
    void Stop() override;
    void Reset() override;

    [[nodiscard]] bool IsStopping() const override;
    [[nodiscard]] const tailgate::crypto::Bytes32& NodePrivateKey() const override;
    [[nodiscard]] const tailgate::crypto::Bytes32& NodePublicKey() const override;
    [[nodiscard]] const tailgate::crypto::Bytes32& DiscoPrivateKey() const override;

private:
    class RegistrationHandler;

    [[nodiscard]] bool WaitForRetry(std::chrono::milliseconds delay) const;
    void Report(SessionEventKind kind);

    SessionManager& m_sessionManager;
    tailgate::control::client::SessionFactory& m_controlSessionFactory;
    TcpSocketFactory& m_socketFactory;
    std::stop_source m_openCancellation;
    std::string m_networkInterface;
    std::vector<tailgate::control::client::MapEndpoint> m_endpoints;
    bool m_refreshEndpoints = false;
    bool m_maintenanceActive = false;
    int m_preferredDerp = 0;
    SessionGeneration m_generation = 0;
    tailgate::crypto::Bytes32 m_machinePrivateKey{};
    tailgate::crypto::Bytes32 m_nodePrivateKey{};
    tailgate::crypto::Bytes32 m_nodePublicKey{};
    tailgate::crypto::Bytes32 m_discoPrivateKey{};
    std::unique_ptr<tailgate::control::client::Session> m_controlSession;
    mutable std::mutex m_mutex;
    mutable std::condition_variable m_stopChanged;
    std::atomic_bool m_stopping = false;
    std::thread m_maintenanceThread;
    tailgate::base::Logger m_logger{"uwp-control-plane"};
};

} // namespace tailgate::uwp::bg::manager
