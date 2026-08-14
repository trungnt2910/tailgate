#pragma once

#include <tailgate/base/ByteStream.h>

#include <memory>
#include <string>

namespace tailgate::linux_frontend
{

[[nodiscard]] int PeerApiWaitTimeout(const tailgate::base::IByteStream& stream);

class LinuxPeerApiServer
{
public:
    LinuxPeerApiServer(const std::string& tailnetAddress,
                       int peerApiPort,
                       std::string funnelTarget,
                       int localPort,
                       std::string certificatePem,
                       std::string privateKeyPem);
    ~LinuxPeerApiServer();

    LinuxPeerApiServer(const LinuxPeerApiServer&) = delete;
    LinuxPeerApiServer& operator=(const LinuxPeerApiServer&) = delete;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace tailgate::linux_frontend
