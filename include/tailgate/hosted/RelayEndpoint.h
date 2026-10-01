#pragma once

#include <optional>
#include <string>

#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::hosted
{

struct RelayEndpoint
{
    std::string Host;
    std::string ConnectAddress;
    std::string Port;

    [[nodiscard]] static RelayEndpoint Parse(const std::string& url);
    // Bootstrap worker only. The socket factory supplies platform DNS/TLS/bypass behavior.
    void Resolve(types::nettype::TcpSocketFactory& sockets,
                 const std::optional<std::string>& networkInterface,
                 std::size_t addressAttempt,
                 std::stop_token cancellation = {},
                 bool allowTls13 = true);
};

} // namespace tailgate::hosted
