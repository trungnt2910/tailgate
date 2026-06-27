#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tailgate
{

struct PeerStatus
{
    std::string Address;
    std::string Hostname;
    std::string OperatingSystem;
    std::string Relay;
    std::string Endpoint;
    bool Online = false;
    bool Active = false;
    bool Direct = false;
    bool ExitNodeOption = false;
    std::uint64_t TxBytes = 0;
    std::uint64_t RxBytes = 0;
};

struct Status
{
    std::int64_t ProcessId = 0;
    std::string BackendState = "Stopped";
    bool Online = false;
    std::string Address;
    std::string Hostname;
    std::string OperatingSystem;
    std::string OperatingSystemVersion;
    std::string ClientVersion;
    std::string Error;
    std::vector<PeerStatus> Peers;
};

} // namespace tailgate
