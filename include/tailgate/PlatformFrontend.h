#pragma once

#include "tailgate/Status.h"
#include "tailgate/cli/Arguments.h"

#include <cstdint>
#include <memory>
#include <string>

namespace tailgate::platform
{

struct PingResult
{
    bool Responded = false;
    bool Local = false;
    std::string NodeName;
    std::string NodeAddress;
    std::string Endpoint;
    std::string Relay;
    int LatencyMilliseconds = 0;
    std::uint16_t PeerApiPort = 0;
};

struct UpResult
{
    bool Ready = false;
};

class IPlatformFrontend
{
public:
    virtual ~IPlatformFrontend() = default;
    virtual UpResult Up(const cli::UpOptions& options) = 0;
    virtual int Down() = 0;
    virtual int Logout() = 0;
    virtual int Set(const cli::SetOptions& options) = 0;
    virtual int Funnel(const cli::FunnelOptions& options) = 0;
    virtual int Expose(const cli::ExposeOptions& options) = 0;
    [[nodiscard]] virtual tailgate::Status ReadStatus() = 0;
    [[nodiscard]] virtual PingResult
    PingOnce(const std::string& target, int timeoutSeconds, std::uint16_t sequence, bool tsmp) = 0;
};

[[nodiscard]] std::unique_ptr<IPlatformFrontend> CreateFrontend();

} // namespace tailgate::platform
