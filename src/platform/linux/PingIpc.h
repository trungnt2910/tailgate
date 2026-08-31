#pragma once

#include <cstdint>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>

#include <tailgate/PlatformFrontend.h>

#include "UniqueFd.h"

namespace tailgate::linux_frontend
{

struct PingRequest
{
    std::string Target;
    int TimeoutSeconds = 0;
    bool Tsmp = false;
};

struct PingResponse
{
    bool Responded = false;
    int LatencyMilliseconds = 0;
    std::string NodeName;
    std::string NodeAddress;
    std::string Endpoint;
    std::string Relay;
    std::uint16_t PeerApiPort = 0;
};

[[nodiscard]] const std::string& PingSocketPath();
[[nodiscard]] UniqueFd OpenPingServer();
[[nodiscard]] bool
ReceivePingRequest(int fd, PingRequest& request, sockaddr_un& client, socklen_t& clientLength);
void SendPingResponse(int fd,
                      const sockaddr_un& client,
                      socklen_t clientLength,
                      const PingResponse& response);
[[nodiscard]] platform::PingResult
RequestDaemonPing(const std::string& target, int timeoutSeconds, bool tsmp);

} // namespace tailgate::linux_frontend
