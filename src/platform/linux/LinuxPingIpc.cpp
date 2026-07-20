#include "LinuxPingIpc.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <format>
#include <optional>
#include <poll.h>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include "LinuxState.h"

namespace tailgate::linux_frontend
{
namespace
{

constexpr std::size_t MaximumPingDatagramSize = 64U * 1024U;

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

std::optional<std::string>
ReceiveDatagram(int fd, sockaddr_un* client = nullptr, socklen_t* clientLength = nullptr)
{
    const ssize_t size = recvfrom(
        fd, nullptr, 0, MSG_PEEK | MSG_TRUNC, reinterpret_cast<sockaddr*>(client), clientLength);
    if (size <= 0)
    {
        return std::nullopt;
    }
    if (static_cast<std::size_t>(size) > MaximumPingDatagramSize)
    {
        (void)recv(fd, nullptr, 0, 0);
        return std::nullopt;
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    if (recv(fd, result.data(), result.size(), 0) != size)
    {
        return std::nullopt;
    }
    return result;
}

std::optional<nlohmann::json> ParseMessage(std::string_view encoded)
{
    nlohmann::json message = nlohmann::json::parse(encoded, nullptr, false);
    return message.is_object() ? std::optional<nlohmann::json>(std::move(message)) : std::nullopt;
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
    const std::optional<std::string> encoded = ReceiveDatagram(fd, &client, &clientLength);
    const std::optional<nlohmann::json> message = encoded ? ParseMessage(*encoded) : std::nullopt;
    if (!message || !message->contains("target") || !message->at("target").is_string())
    {
        return false;
    }
    request.Target = message->at("target").get<std::string>();
    request.TimeoutSeconds = message->value("timeoutSeconds", 0);
    request.Tsmp = message->value("tsmp", false);
    return !request.Target.empty();
}

void SendPingResponse(int fd,
                      const sockaddr_un& client,
                      socklen_t clientLength,
                      const PingResponse& response)
{
    const std::string encoded =
        nlohmann::json{
            {"responded", response.Responded},
            {"latencyMilliseconds", response.LatencyMilliseconds},
            {"nodeName", response.NodeName},
            {"nodeAddress", response.NodeAddress},
            {"endpoint", response.Endpoint},
            {"relay", response.Relay},
            {"peerApiPort", response.PeerApiPort},
        }
            .dump();
    (void)sendto(fd,
                 encoded.data(),
                 encoded.size(),
                 0,
                 reinterpret_cast<const sockaddr*>(&client),
                 clientLength);
}

platform::PingResult RequestDaemonPing(const std::string& target, int timeoutSeconds, bool tsmp)
{
    UniqueFd fd(socket(AF_UNIX, SOCK_DGRAM, 0));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("failed to create ping client socket");
    }
    const std::string clientPath = std::format("{}/ping-{}.sock", StateDirectory(), getpid());
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

    const std::string request =
        nlohmann::json{
            {"target", target},
            {"timeoutSeconds", timeoutSeconds},
            {"tsmp", tsmp},
        }
            .dump();
    sockaddr_un server{};
    SetPath(server, PingSocketPath());
    if (sendto(fd.Fd,
               request.data(),
               request.size(),
               0,
               reinterpret_cast<const sockaddr*>(&server),
               sizeof(server)) < 0)
    {
        throw std::runtime_error("Tailgate daemon is not accepting ping requests");
    }
    pollfd descriptor{.fd = fd.Fd, .events = POLLIN, .revents = 0};
    if (poll(&descriptor, 1, (timeoutSeconds + 1) * 1000) <= 0)
    {
        return {};
    }
    const std::optional<std::string> encoded = ReceiveDatagram(fd.Fd);
    const std::optional<nlohmann::json> message = encoded ? ParseMessage(*encoded) : std::nullopt;
    if (!message)
    {
        return {};
    }
    const PingResponse response{
        .Responded = message->value("responded", false),
        .LatencyMilliseconds = message->value("latencyMilliseconds", 0),
        .NodeName = message->value("nodeName", ""),
        .NodeAddress = message->value("nodeAddress", ""),
        .Endpoint = message->value("endpoint", ""),
        .Relay = message->value("relay", ""),
        .PeerApiPort = message->value("peerApiPort", std::uint16_t{}),
    };
    if (response.NodeName.empty() && response.NodeAddress.empty())
    {
        throw std::runtime_error("no matching tailnet peer for " + target);
    }
    return platform::PingResult{.Responded = response.Responded,
                                .Local = false,
                                .NodeName = response.NodeName,
                                .NodeAddress = response.NodeAddress,
                                .Endpoint = response.Endpoint,
                                .Relay = response.Relay,
                                .LatencyMilliseconds = response.LatencyMilliseconds,
                                .PeerApiPort = response.PeerApiPort};
}

} // namespace tailgate::linux_frontend
