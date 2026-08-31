#pragma once

#include <memory>
#include <string>

#include <tailgate/base/ByteStream.h>

namespace tailgate::linux_frontend
{

[[nodiscard]] int PeerApiWaitTimeout(const tailgate::base::ByteStream& stream);

class PeerApiServer
{
public:
    PeerApiServer(const std::string& tailnetAddress,
                  int peerApiPort,
                  std::string funnelTarget,
                  int localPort,
                  std::string certificatePem,
                  std::string privateKeyPem);
    ~PeerApiServer();

    PeerApiServer(const PeerApiServer&) = delete;
    PeerApiServer& operator=(const PeerApiServer&) = delete;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace tailgate::linux_frontend
