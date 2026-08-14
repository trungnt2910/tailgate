#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

#include <tailgate/base/ByteStream.h>
#include <tailgate/base/Logger.h>
#include <tailgate/control/client/ControlClient.h>

#include "manager/ControlPlaneManager.h"

namespace tailgate::uwp
{

class UwpTcpStream;

}

namespace tailgate::uwp::bg::manager
{

class ControlPlaneManagerImpl final : public ControlPlaneManager
{
public:
    explicit ControlPlaneManagerImpl(SessionManager& sessionManager);
    ~ControlPlaneManagerImpl() override;

    void Start(SessionGeneration generation) override;
    void LoadIdentity(bool registered) override;
    [[nodiscard]] tailgate::control::client::RegistrationResult
    Connect(const std::string& authKey) override;
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
    [[nodiscard]] bool WaitForRetry(std::chrono::milliseconds delay) const;
    void Report(SessionEventKind kind);

    SessionManager& m_sessionManager;
    SessionGeneration m_generation = 0;
    tailgate::crypto::Bytes32 m_machinePrivateKey{};
    tailgate::crypto::Bytes32 m_nodePrivateKey{};
    tailgate::crypto::Bytes32 m_nodePublicKey{};
    tailgate::crypto::Bytes32 m_discoPrivateKey{};
    std::unique_ptr<UwpTcpStream> m_stream;
    std::unique_ptr<tailgate::control::client::ControlClient> m_client;
    mutable std::mutex m_mutex;
    std::atomic_bool m_stopping = false;
    std::thread m_maintenanceThread;
    tailgate::base::Logger m_logger{"uwp-control-plane"};
};

} // namespace tailgate::uwp::bg::manager
