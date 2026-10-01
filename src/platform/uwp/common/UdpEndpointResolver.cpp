#include "UdpEndpointResolver.h"

#include <chrono>
#include <system_error>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Networking.h>

#include "ThreadApartment.h"
#include "WinrtOperation.h"

namespace tailgate::uwp
{

tailgate::net::Endpoint UdpEndpointResolver::Resolve(const std::string& host,
                                                     std::uint16_t port,
                                                     std::stop_token cancellation) const
{
    ThreadApartment::Ensure();
    constexpr auto ResolveTimeout = std::chrono::seconds(10);
    const auto pairs = AwaitOperation(
        winrt::Windows::Networking::Sockets::DatagramSocket::GetEndpointPairsAsync(
            winrt::Windows::Networking::HostName(winrt::to_hstring(host)), winrt::to_hstring(port)),
        ResolveTimeout,
        cancellation);
    for (const auto& pair : pairs)
    {
        if (const auto address = tailgate::net::Ipv4Address::TryParse(
                winrt::to_string(pair.RemoteHostName().CanonicalName())))
        {
            return tailgate::net::Endpoint(*address, port);
        }
    }
    throw std::system_error(std::make_error_code(std::errc::host_unreachable));
}

} // namespace tailgate::uwp
