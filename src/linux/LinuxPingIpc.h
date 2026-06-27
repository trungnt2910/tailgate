#pragma once

#include "UniqueFd.h"
#include "tailgate/PlatformFrontend.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>

namespace tailgate::linux_frontend
{

constexpr std::size_t PingTextSize = 256;

struct PingRequest
{
    char Target[PingTextSize]{};
    int TimeoutSeconds = 0;
};

struct PingResponse
{
    int Responded = 0;
    int LatencyMilliseconds = 0;
    char NodeName[PingTextSize]{};
    char NodeAddress[PingTextSize]{};
    char Endpoint[PingTextSize]{};
    char Relay[PingTextSize]{};
};

[[nodiscard]] const std::string& PingSocketPath();
[[nodiscard]] UniqueFd OpenPingServer();
[[nodiscard]] bool
ReceivePingRequest(int fd, PingRequest& request, sockaddr_un& client, socklen_t& clientLength);
void SendPingResponse(int fd,
                      const sockaddr_un& client,
                      socklen_t clientLength,
                      const PingResponse& response);
[[nodiscard]] platform::PingResult RequestDaemonPing(const std::string& target, int timeoutSeconds);

} // namespace tailgate::linux_frontend
