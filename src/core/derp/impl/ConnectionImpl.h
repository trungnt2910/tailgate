#pragma once

#include <chrono>
#include <memory>

#include <tailgate/base/Logger.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::derp::impl
{

class ConnectionImpl final : public tailgate::derp::Connection
{
public:
    ConnectionImpl(tailgate::derp::ConnectionOptions options,
                   tailgate::types::nettype::TcpSocketFactory& socketFactory,
                   tailgate::base::TimeProvider& timeProvider);
    ~ConnectionImpl() override;

    void Send(const tailgate::derp::DerpClient::Key& destination,
              std::vector<std::uint8_t> packet,
              tailgate::derp::DerpSendQueue::Priority priority) override;
    [[nodiscard]] tailgate::derp::ConnectionEventResult
    ProcessEvent(const tailgate::base::Event& event) override;
    void Maintain() override;
    [[nodiscard]] bool Connected() const noexcept override;

private:
    void Connect();
    void Disconnect() noexcept;
    void ScheduleReconnect() noexcept;
    void FlushOutgoing();
    [[nodiscard]] std::vector<tailgate::derp::DerpClient::Packet> DrainIncoming();
    void UpdateWriteInterest();

    static constexpr std::chrono::seconds InitialReconnectDelay{1};
    static constexpr std::chrono::seconds MaximumReconnectDelay{30};
    static constexpr std::size_t MaximumQueuedPackets = 4096;
    static constexpr std::size_t MaximumQueuedBytes = 8U * 1024U * 1024U;
    static constexpr std::size_t MaximumFramesPerFlush = 64;

    tailgate::derp::ConnectionOptions m_options;
    tailgate::types::nettype::TcpSocketFactory& m_socketFactory;
    tailgate::base::TimeProvider& m_timeProvider;
    std::unique_ptr<tailgate::types::nettype::TcpSocket> m_socket;
    std::unique_ptr<tailgate::derp::DerpClient> m_client;
    tailgate::derp::DerpSendQueue m_outgoing{MaximumQueuedPackets, MaximumQueuedBytes};
    tailgate::base::TimeProvider::TimePoint m_nextReconnect{};
    std::chrono::seconds m_reconnectDelay = InitialReconnectDelay;
    tailgate::base::Logger m_logger{"derp"};
};

class ConnectionFactoryImpl final : public tailgate::derp::ConnectionFactory
{
public:
    ConnectionFactoryImpl(tailgate::types::nettype::TcpSocketFactory& socketFactory,
                          tailgate::base::TimeProvider& timeProvider) noexcept;

    [[nodiscard]] std::unique_ptr<tailgate::derp::Connection>
    CreateConnection(tailgate::derp::ConnectionOptions options) override;

private:
    tailgate::types::nettype::TcpSocketFactory& m_socketFactory;
    tailgate::base::TimeProvider& m_timeProvider;
};

} // namespace tailgate::derp::impl
