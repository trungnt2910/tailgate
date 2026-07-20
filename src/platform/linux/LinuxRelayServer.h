#pragma once

#include "tailgate/ByteStream.h"

#include <functional>
#include <memory>

namespace tailgate::linux_frontend
{

class LinuxRelayServer final
{
public:
    using Handler = std::function<void(IByteStream&,
                                       const std::function<void()>& closeConnection,
                                       const std::function<void()>& markIdentityVerified)>;

    LinuxRelayServer(int port, Handler handler);
    ~LinuxRelayServer();

    LinuxRelayServer(const LinuxRelayServer&) = delete;
    LinuxRelayServer& operator=(const LinuxRelayServer&) = delete;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace tailgate::linux_frontend
