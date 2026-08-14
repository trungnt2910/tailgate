#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/derp/Client.h>
#include <tailgate/derp/SendQueue.h>

namespace tailgate::linux_frontend
{

class DerpWorker
{
public:
    using Key = tailgate::derp::DerpClient::Key;
    using Packet = tailgate::derp::DerpClient::Packet;

    using Priority = tailgate::derp::DerpSendQueue::Priority;

    DerpWorker(const std::string& host,
               const std::string& interfaceName,
               const tailgate::crypto::Bytes32& privateKey,
               const tailgate::crypto::Bytes32& publicKey,
               bool preferred,
               tailgate::derp::DerpClient::Authenticator authenticator = {});
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
