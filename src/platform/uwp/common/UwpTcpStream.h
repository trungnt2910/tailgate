#pragma once

#include <chrono>
#include <optional>
#include <string>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Storage.Streams.h>

#include <tailgate/base/ByteStream.h>
#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

namespace tailgate::uwp
{

// TCP stream over a WinRT StreamSocket. TLS always uses a plain TCP connect followed by an
// explicit UpgradeToSslAsync handshake: connecting with a TLS protection level directly defers
// the handshake to the first I/O, which hangs inside the VPN background process.
class UwpTcpStream final : public tailgate::base::IByteStream
{
public:
    // An unset connect timeout uses the I/O timeout. A short connect timeout lets dial-with-
    // fallback strategies abandon an unresponsive endpoint quickly while keeping long steady-
    // state read timeouts.
    UwpTcpStream(winrt::Windows::Networking::Sockets::StreamSocket socket,
                 const std::string& host,
                 const std::string& service,
                 winrt::Windows::Networking::Sockets::SocketProtectionLevel protection,
                 std::chrono::seconds timeout = std::chrono::seconds(20),
                 const std::string& tlsValidationHost = {},
                 std::optional<std::chrono::seconds> connectTimeout = std::nullopt);

    UwpTcpStream(const std::string& host,
                 const std::string& service,
                 winrt::Windows::Networking::Sockets::SocketProtectionLevel protection,
                 std::chrono::seconds timeout = std::chrono::seconds(20),
                 std::optional<std::chrono::seconds> connectTimeout = std::nullopt);

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override;
    void SetReadTimeout(std::optional<std::chrono::seconds> timeout);
    void SetNonBlockingReads(bool enabled);
    void WaitForPendingRead();
    void Close();

private:
    winrt::Windows::Networking::Sockets::StreamSocket m_socket;
    winrt::Windows::Storage::Streams::IInputStream m_input{nullptr};
    winrt::Windows::Storage::Streams::IOutputStream m_output{nullptr};
    std::chrono::seconds m_ioTimeout;
    std::optional<std::chrono::seconds> m_readTimeout;
    winrt::Windows::Foundation::
        IAsyncOperationWithProgress<winrt::Windows::Storage::Streams::IBuffer, std::uint32_t>
            m_pendingRead{nullptr};
    bool m_nonBlockingReads = false;
    tailgate::base::Logger m_logger{"uwp-tcp"};
};

} // namespace tailgate::uwp
