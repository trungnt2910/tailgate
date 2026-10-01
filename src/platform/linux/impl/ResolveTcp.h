#pragma once

#include <chrono>
#include <stop_token>
#include <string>
#include <vector>

#include <sys/socket.h>

namespace tailgate::linux_frontend::impl
{

struct TcpAddress
{
    sockaddr_storage Address{};
    socklen_t Length = 0;
    int Family = 0;
    int Protocol = 0;
};

[[nodiscard]] std::vector<TcpAddress> ResolveTcp(const std::string& host,
                                                 const std::string& service,
                                                 std::chrono::seconds timeout,
                                                 std::stop_token cancellation);

} // namespace tailgate::linux_frontend::impl
