#include "UwpTcpStream.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.h>

#include "NetworkAdapter.h"
#include "ThreadApartment.h"
#include "WinrtOperation.h"

namespace tailgate::uwp
{
namespace
{

namespace foundation = winrt::Windows::Foundation;
namespace networking = winrt::Windows::Networking;
namespace sockets = winrt::Windows::Networking::Sockets;
namespace streams = winrt::Windows::Storage::Streams;

} // namespace

UwpTcpStream::~UwpTcpStream()
{
    Close();
}

UwpTcpStream::UwpTcpStream(sockets::StreamSocket socket,
                           const tailgate::types::nettype::TcpSocketOptions& options)
    : m_socket(std::move(socket))
{
    ThreadApartment::Ensure();
    m_logger.LogDebug("tcp connect {}:{}", options.ConnectAddress, options.Service);
    const auto adapter = NetworkAdapter(options.NetworkInterface).Native();
    const networking::HostName address(winrt::to_hstring(options.ConnectAddress));
    const auto service = winrt::to_hstring(options.Service);
    auto connect =
        adapter
            ? m_socket.ConnectAsync(
                  address, service, sockets::SocketProtectionLevel::PlainSocket, adapter)
            : m_socket.ConnectAsync(address, service, sockets::SocketProtectionLevel::PlainSocket);
    AwaitOperation(
        connect, options.ConnectTimeout.value_or(options.IoTimeout), options.Cancellation);
    if (options.TlsServerName)
    {
        m_logger.LogDebug("tcp TLS upgrade validation-host={}", *options.TlsServerName);
        auto upgrade = m_socket.UpgradeToSslAsync(
            sockets::SocketProtectionLevel::Tls12,
            networking::HostName(winrt::to_hstring(*options.TlsServerName)));
        AwaitOperation(upgrade, options.IoTimeout, options.Cancellation);
    }
    m_io = std::make_unique<UwpStreamIo>(m_socket.InputStream(),
                                         m_socket.OutputStream(),
                                         StreamIoOptions{.Timeout = options.IoTimeout,
                                                         .Cancellation = options.Cancellation,
                                                         .Events = options.ReadinessEvents,
                                                         .Token = options.ReadinessToken});
    m_logger.LogDebug("tcp connected");
}

std::optional<std::size_t> UwpTcpStream::TryWriteSome(const std::uint8_t* data, std::size_t size)
{
    return m_io->TryWriteSome(data, size);
}

std::optional<std::vector<std::uint8_t>> UwpTcpStream::TryReadSome(std::size_t maximumSize)
{
    return m_io->TryReadSome(maximumSize);
}

bool UwpTcpStream::HasBufferedInput() const
{
    return m_io->HasBufferedInput();
}

void UwpTcpStream::SetReadTimeout(std::optional<std::chrono::seconds> timeout)
{
    m_io->SetReadTimeout(timeout);
}

void UwpTcpStream::SetWriteInterest(bool enabled)
{
    m_io->SetWriteInterest(enabled);
}

void UwpTcpStream::SetNonBlocking(bool enabled)
{
    m_io->SetNonBlocking(enabled);
}

void UwpTcpStream::Close() noexcept
{
    if (m_io)
    {
        m_io->Close();
    }
    try
    {
        m_socket.Close();
    }
    catch (...)
    { /* The socket may already be closed during teardown. */
    }
}

} // namespace tailgate::uwp
