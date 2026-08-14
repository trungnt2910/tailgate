#pragma once

#include <chrono>
#include <string>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

namespace tailgate::uwp
{

class TailgateRelay final
{
public:
    TailgateRelay(std::string host, std::string service);

    void Resolve();
    void UseCachedEndpoint(std::string connectAddress, std::string validationHost);
    void Preflight(std::chrono::seconds timeout);

    [[nodiscard]] const std::string& Host() const noexcept;
    [[nodiscard]] const std::string& Service() const noexcept;
    [[nodiscard]] const std::string& ConnectAddress() const noexcept;
    [[nodiscard]] bool IsUsingCachedEndpoint() const noexcept;

private:
    std::string m_requestHost;
    std::string m_validationHost;
    std::string m_service;
    std::string m_connectAddress;
    bool m_usingCachedEndpoint = false;
    tailgate::base::Logger m_logger{"uwp-relay"};
};

} // namespace tailgate::uwp
