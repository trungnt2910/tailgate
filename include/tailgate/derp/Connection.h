#pragma once

#include <memory>
#include <string>
#include <vector>

#include <tailgate/base/EventLoop.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/derp/Client.h>
#include <tailgate/derp/SendQueue.h>

namespace tailgate::derp
{

struct ConnectionOptions
{
    std::string Host;
    std::string NetworkInterface;
    tailgate::crypto::Bytes32 PrivateKey{};
    tailgate::crypto::Bytes32 PublicKey{};
    tailgate::derp::DerpClient::Authenticator Authenticator;
    tailgate::base::EventToken ReadinessToken;
    bool Preferred = false;
};

enum class ConnectionEventStatus
{
    Ready,
    Disconnected,
};

struct ConnectionEventResult
{
    bool Handled = false;
    ConnectionEventStatus Status = ConnectionEventStatus::Ready;
    std::vector<tailgate::derp::DerpClient::Packet> Packets;
};

class Connection
{
public:
    virtual ~Connection();

    virtual void Send(const tailgate::derp::DerpClient::Key& destination,
                      std::vector<std::uint8_t> packet,
                      tailgate::derp::DerpSendQueue::Priority priority =
                          tailgate::derp::DerpSendQueue::Priority::Data) = 0;
    [[nodiscard]] virtual ConnectionEventResult
    ProcessEvent(const tailgate::base::Event& event) = 0;
    virtual void Maintain() = 0;
    [[nodiscard]] virtual bool Connected() const noexcept = 0;

protected:
    Connection() = default;
};

class ConnectionFactory
{
public:
    virtual ~ConnectionFactory();

    [[nodiscard]] virtual std::unique_ptr<Connection>
    CreateConnection(ConnectionOptions options) = 0;

protected:
    ConnectionFactory() = default;
};

} // namespace tailgate::derp
