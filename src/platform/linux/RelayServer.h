#pragma once

#include <functional>
#include <memory>

#include <tailgate/base/ByteStream.h>

namespace tailgate::linux_frontend
{

class RelayServer final
{
public:
    using Handler = std::function<void(tailgate::base::ByteStream&,
                                       const std::function<void()>& closeConnection,
                                       const std::function<void()>& markIdentityVerified)>;

    RelayServer(int port, Handler handler);
    ~RelayServer();

    RelayServer(const RelayServer&) = delete;
    RelayServer& operator=(const RelayServer&) = delete;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace tailgate::linux_frontend
