#pragma once

#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/DerpClient.h"
#include "tailgate/protocol/DerpSendQueue.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tailgate::linux_frontend
{

class DerpWorker
{
public:
    using Key = protocol::DerpClient::Key;
    using Packet = protocol::DerpClient::Packet;

    using Priority = protocol::DerpSendQueue::Priority;

    DerpWorker(const std::string& host,
               const std::string& interfaceName,
               const protocol::Bytes32& privateKey,
               const protocol::Bytes32& publicKey,
               bool preferred,
               protocol::DerpClient::Authenticator authenticator = {});
    ~DerpWorker();

    DerpWorker(const DerpWorker&) = delete;
    DerpWorker& operator=(const DerpWorker&) = delete;

    [[nodiscard]] int NotifyFd() const;
    void Send(const Key& destination,
              std::vector<std::uint8_t> packet,
              Priority priority = Priority::Data);
    [[nodiscard]] std::vector<Packet> ReceivePackets();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace tailgate::linux_frontend
