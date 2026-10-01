#pragma once

#include <chrono>
#include <optional>
#include <stop_token>
#include <string>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Storage.Streams.h>

#include <tailgate/base/Logger.h>
#include <tailgate/types/nettype/TcpSocket.h>

#include "common/UwpFormat.h"

#include "UwpStreamIo.h"

namespace tailgate::uwp
{

// TCP stream over a WinRT StreamSocket. TLS always uses a plain TCP connect followed by an
// explicit UpgradeToSslAsync handshake: connecting with a TLS protection level directly defers
// the handshake to the first I/O, which hangs inside the VPN background process.
class UwpTcpStream final : public tailgate::types::nettype::TcpSocket
{
public:
    UwpTcpStream(winrt::Windows::Networking::Sockets::StreamSocket socket,
                 const tailgate::types::nettype::TcpSocketOptions& options);
    ~UwpTcpStream() override;

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override;
    [[nodiscard]] bool HasBufferedInput() const override;
    void SetReadTimeout(std::optional<std::chrono::seconds> timeout) override;
    void SetWriteInterest(bool enabled) override;
    void SetNonBlocking(bool enabled) override;
    void Close() noexcept override;

private:
    winrt::Windows::Networking::Sockets::StreamSocket m_socket;
    std::unique_ptr<UwpStreamIo> m_io;
    tailgate::base::Logger m_logger{"uwp-tcp"};
};

} // namespace tailgate::uwp
