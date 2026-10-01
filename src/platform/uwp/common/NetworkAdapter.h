#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <winrt/Windows.Networking.Connectivity.h>

#include <tailgate/net/Ipv4Address.h>

namespace tailgate::uwp
{

class NetworkAdapterUnavailable final : public std::runtime_error
{
public:
    NetworkAdapterUnavailable();
};

// Resolves an explicit adapter identifier without silently falling back to OS routing.
// An absent identifier retains ordinary OS routing for sockets outside the VPN worker.
class NetworkAdapter final
{
public:
    explicit NetworkAdapter(const std::optional<std::string>& identifier);

    [[nodiscard]] const winrt::Windows::Networking::Connectivity::NetworkAdapter&
    Native() const noexcept;
    [[nodiscard]] tailgate::net::Ipv4Address Ipv4Address() const;

    // Connectivity ranking only; a successful dial establishes reachability.
    [[nodiscard]] static std::vector<std::string> Candidates();

private:
    winrt::Windows::Networking::Connectivity::NetworkAdapter m_adapter{nullptr};
};

} // namespace tailgate::uwp
