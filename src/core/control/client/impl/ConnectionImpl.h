#pragma once

#include <atomic>
#include <chrono>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include <tailgate/base/Logger.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/control/client/Connection.h>
#include <tailgate/control/client/HostInfoProvider.h>
#include <tailgate/control/client/Session.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::control::client::impl
{

class ConnectionImpl final : public tailgate::control::client::Connection
{
public:
    ConnectionImpl(tailgate::control::client::SessionOptions options,
                   tailgate::control::client::SessionFactory& sessionFactory,
                   tailgate::types::nettype::TcpSocketFactory& socketFactory,
                   tailgate::base::TimeProvider& timeProvider,
                   tailgate::base::EventLoop& eventLoop);
    ~ConnectionImpl() override;

    [[nodiscard]] tailgate::control::client::RegistrationResult
    RegisterUntilAuthorized(const std::string& authKey,
                            const tailgate::control::client::RegistrationOptions& options) override;
    [[nodiscard]] tailgate::types::netmap::NetworkConfig RequestNetworkMap() override;
    [[nodiscard]] tailgate::control::client::FeatureEnablement
    QueryFeature(const std::string& feature) override;
    void SetDnsTxt(const std::string& name, const std::string& value) override;
    void UpdateHostInfo(int preferredDerp) override;
    void SetDiscoPrivateKey(const tailgate::crypto::Bytes32& privateKey) override;
    void SetEndpoints(std::vector<tailgate::control::client::MapEndpoint> endpoints) override;
    void SetPreferredDerp(int region) override;
    void StartStreaming() override;
    [[nodiscard]] tailgate::control::client::ConnectionEventResult
    ProcessEvent(const tailgate::base::Event& event) override;
    [[nodiscard]] std::vector<tailgate::types::netmap::NetworkConfig> Maintain() override;
    void RequestReconnect() noexcept override;
    void Logout() override;
    [[nodiscard]] const tailgate::crypto::Bytes32& NodePublicKey() const override;
    [[nodiscard]] const tailgate::crypto::Bytes32& DiscoPrivateKey() const override;
    [[nodiscard]] bool Connected() const noexcept override;

private:
    struct ReconnectResult
    {
        std::unique_ptr<tailgate::control::client::Session> Session;
        std::optional<tailgate::types::netmap::NetworkConfig> Network;
        std::exception_ptr Error;
    };

    void Connect();
    void Disconnect() noexcept;
    void ScheduleReconnect() noexcept;
    void StartReconnect();
    [[nodiscard]] std::optional<ReconnectResult> TakeReconnectResult();
    [[nodiscard]] tailgate::control::client::Session& ActiveSession();
    [[nodiscard]] const tailgate::control::client::Session& ActiveSession() const;
    [[nodiscard]] std::vector<tailgate::types::netmap::NetworkConfig> PollNetworkMaps();
    void UpdateWriteInterest();

    static constexpr std::chrono::minutes SilenceTimeout{2};
    static constexpr std::chrono::seconds InitialReconnectDelay{1};
    static constexpr std::chrono::seconds MaximumReconnectDelay{30};

    tailgate::control::client::SessionOptions m_options;
    tailgate::control::client::SessionFactory& m_sessionFactory;
    tailgate::types::nettype::TcpSocketFactory& m_socketFactory;
    tailgate::base::TimeProvider& m_timeProvider;
    tailgate::base::EventLoop& m_eventLoop;
    std::unique_ptr<tailgate::control::client::Session> m_session;
    std::thread m_reconnectThread;
    std::mutex m_reconnectMutex;
    std::optional<ReconnectResult> m_reconnectResult;
    std::optional<tailgate::crypto::Bytes32> m_discoPrivateKey;
    std::optional<std::vector<tailgate::control::client::MapEndpoint>> m_endpoints;
    std::optional<int> m_preferredDerp;
    tailgate::base::TimeProvider::TimePoint m_lastActivity{};
    tailgate::base::TimeProvider::TimePoint m_nextReconnect{};
    std::chrono::seconds m_reconnectDelay = InitialReconnectDelay;
    bool m_streaming = false;
    bool m_reconnecting = false;
    bool m_reconnectInProgress = false;
    std::atomic_bool m_reconnectRequested = false;
    tailgate::base::Logger m_logger{"control"};
};

class ConnectionFactoryImpl final : public tailgate::control::client::ConnectionFactory
{
public:
    ConnectionFactoryImpl(tailgate::control::client::SessionFactory& sessionFactory,
                          tailgate::types::nettype::TcpSocketFactory& socketFactory,
                          tailgate::base::TimeProvider& timeProvider,
                          tailgate::base::EventLoop& eventLoop) noexcept;

    [[nodiscard]] std::unique_ptr<tailgate::control::client::Connection>
    CreateConnection(tailgate::control::client::SessionOptions options) override;

private:
    tailgate::control::client::SessionFactory& m_sessionFactory;
    tailgate::types::nettype::TcpSocketFactory& m_socketFactory;
    tailgate::base::TimeProvider& m_timeProvider;
    tailgate::base::EventLoop& m_eventLoop;
};

} // namespace tailgate::control::client::impl
