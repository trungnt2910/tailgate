#pragma once

#include "UniqueFd.h"

#include <chrono>
#include <cstdint>

namespace tailgate::linux_frontend
{

enum class DataplaneEventKind : std::uint32_t
{
    Tun,
    LocalDns,
    Derp,
    UpstreamDns,
    Ping,
    Peer,
    Maintenance,
    Control,
};

struct DataplaneEvent
{
    DataplaneEventKind Kind;
    std::uint32_t Index;
};

[[nodiscard]] std::uint64_t PackDataplaneEvent(DataplaneEventKind kind, std::uint32_t index = 0);
[[nodiscard]] DataplaneEvent UnpackDataplaneEvent(std::uint64_t value);
void AddEpollInterest(int epollFd, int fd, std::uint32_t events, std::uint64_t token);
void ModifyEpollInterest(int epollFd, int fd, std::uint32_t events, std::uint64_t token);
[[nodiscard]] UniqueFd CreateTimerFd(std::chrono::nanoseconds interval);
void DrainTimerFd(int fd);

} // namespace tailgate::linux_frontend
