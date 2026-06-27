#include "LinuxPingIpc.h"

#include "LinuxState.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <stdexcept>

#include <sys/socket.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{
namespace
{

void SetPath(sockaddr_un& address, const std::string& path)
{
    if (path.size() >= sizeof(address.sun_path))
    {
        throw std::runtime_error("Tailgate state path is too long");
    }
    address.sun_family = AF_UNIX;
    std::copy(path.begin(), path.end(), address.sun_path);
    address.sun_path[path.size()] = '\0';
}

template <std::size_t Size>
std::string Text(const char (&value)[Size])
{
    return std::string(value, strnlen(value, Size));
}

} // namespace

const std::string& PingSocketPath()
{
    static const std::string path = StateDirectory() + "/ping.sock";
    return path;
}

UniqueFd OpenPingServer()
{
    UniqueFd fd(socket(AF_UNIX, SOCK_DGRAM, 0));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("failed to create ping control socket");
    }
    sockaddr_un address{};
    SetPath(address, PingSocketPath());
    unlink(PingSocketPath().c_str());
    if (bind(fd.Fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
    {
        throw std::runtime_error("failed to bind ping control socket: " +
                                 std::string(std::strerror(errno)));
    }
    return fd;
}

bool ReceivePingRequest(int fd, PingRequest& request, sockaddr_un& client, socklen_t& clientLength)
{
    const ssize_t size = recvfrom(
        fd, &request, sizeof(request), 0, reinterpret_cast<sockaddr*>(&client), &clientLength);
    return size == static_cast<ssize_t>(sizeof(request));
}

void SendPingResponse(int fd,
                      const sockaddr_un& client,
                      socklen_t clientLength,
                      const PingResponse& response)
{
    (void)sendto(fd,
                 &response,
                 sizeof(response),
                 0,
                 reinterpret_cast<const sockaddr*>(&client),
                 clientLength);
}

platform::PingResult RequestDaemonPing(const std::string& target, int timeoutSeconds)
{
    UniqueFd fd(socket(AF_UNIX, SOCK_DGRAM, 0));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("failed to create ping client socket");
    }
    const std::string clientPath = StateDirectory() + "/ping-" + std::to_string(getpid()) + ".sock";
    sockaddr_un client{};
    SetPath(client, clientPath);
    unlink(clientPath.c_str());
    if (bind(fd.Fd, reinterpret_cast<const sockaddr*>(&client), sizeof(client)) != 0)
    {
        throw std::runtime_error("failed to bind ping client socket");
    }
    struct Cleanup
    {
        const std::string& Path;
        ~Cleanup()
        {
            unlink(Path.c_str());
        }
    } cleanup{clientPath};

    PingRequest request{};
    std::copy_n(target.data(), std::min(target.size(), sizeof(request.Target) - 1), request.Target);
    request.TimeoutSeconds = timeoutSeconds;
    sockaddr_un server{};
    SetPath(server, PingSocketPath());
    if (sendto(fd.Fd,
               &request,
               sizeof(request),
               0,
               reinterpret_cast<const sockaddr*>(&server),
               sizeof(server)) < 0)
    {
        throw std::runtime_error("Tailgate daemon is not accepting ping requests");
    }
    pollfd descriptor{fd.Fd, POLLIN, 0};
    if (poll(&descriptor, 1, (timeoutSeconds + 1) * 1000) <= 0)
    {
        return {};
    }
    PingResponse response{};
    if (recv(fd.Fd, &response, sizeof(response), 0) != static_cast<ssize_t>(sizeof(response)))
    {
        return {};
    }
    if (Text(response.NodeName).empty() && Text(response.NodeAddress).empty())
    {
        throw std::runtime_error("no matching tailnet peer for " + target);
    }
    return {
        response.Responded != 0,
        Text(response.NodeName),
        Text(response.NodeAddress),
        Text(response.Endpoint),
        Text(response.Relay),
        response.LatencyMilliseconds,
    };
}

} // namespace tailgate::linux_frontend
