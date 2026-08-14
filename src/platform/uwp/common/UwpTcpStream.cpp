#include "UwpTcpStream.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.h>

namespace tailgate::uwp
{
namespace
{

namespace foundation = winrt::Windows::Foundation;
namespace networking = winrt::Windows::Networking;
namespace sockets = winrt::Windows::Networking::Sockets;
namespace streams = winrt::Windows::Storage::Streams;

template <typename T>
void WaitFor(const T& operation, const char* name, std::chrono::seconds timeout)
{
    if (operation.wait_for(timeout) == foundation::AsyncStatus::Started)
    {
        operation.Cancel();
        throw std::runtime_error(std::string(name) + " timed out.");
    }
    operation.GetResults();
}

template <typename T>
auto ResultWithTimeout(const T& operation, const char* name, std::chrono::seconds timeout)
{
    if (operation.wait_for(timeout) == foundation::AsyncStatus::Started)
    {
        operation.Cancel();
        throw std::runtime_error(std::string(name) + " timed out.");
    }
    return operation.GetResults();
}

template <typename T>
auto ResultWithOptionalTimeout(const T& operation,
                               const char* name,
                               std::optional<std::chrono::seconds> timeout)
{
    if (!timeout)
    {
        return operation.get();
    }
    return ResultWithTimeout(operation, name, *timeout);
}

std::vector<std::uint8_t> BytesFromBuffer(const streams::IBuffer& buffer,
                                          const tailgate::base::Logger& logger)
{
    const std::uint32_t length = buffer.Length();
    logger.LogTrace("tcp read {}", length);
    std::vector<std::uint8_t> result(length);
    if (length != 0)
    {
        streams::DataReader reader = streams::DataReader::FromBuffer(buffer);
        reader.ReadBytes(winrt::array_view<std::uint8_t>(result));
    }
    return result;
}

} // namespace

UwpTcpStream::UwpTcpStream(sockets::StreamSocket socket,
                           const std::string& host,
                           const std::string& service,
                           sockets::SocketProtectionLevel protection,
                           std::chrono::seconds timeout,
                           const std::string& tlsValidationHost,
                           std::optional<std::chrono::seconds> connectTimeout)
    : m_socket(std::move(socket)), m_ioTimeout(timeout), m_readTimeout(timeout)
{
    m_logger.LogDebug("tcp connect {}:{}", host, service);
    const sockets::SocketProtectionLevel connectProtection =
        tlsValidationHost.empty() ? protection : sockets::SocketProtectionLevel::PlainSocket;
    auto connect = m_socket.ConnectAsync(networking::HostName(winrt::to_hstring(host)),
                                         winrt::to_hstring(service),
                                         connectProtection);
    WaitFor(connect, "tcp connect", connectTimeout.value_or(m_ioTimeout));
    if (!tlsValidationHost.empty())
    {
        m_logger.LogDebug("tcp TLS upgrade validation-host={}", tlsValidationHost);
        auto upgrade = m_socket.UpgradeToSslAsync(
            protection, networking::HostName(winrt::to_hstring(tlsValidationHost)));
        WaitFor(upgrade, "tcp TLS upgrade", m_ioTimeout);
    }
    m_input = m_socket.InputStream();
    m_output = m_socket.OutputStream();
    m_logger.LogDebug("tcp connected");
}

UwpTcpStream::UwpTcpStream(const std::string& host,
                           const std::string& service,
                           sockets::SocketProtectionLevel protection,
                           std::chrono::seconds timeout,
                           std::optional<std::chrono::seconds> connectTimeout)
    : UwpTcpStream(sockets::StreamSocket(), host, service, protection, timeout, {}, connectTimeout)
{
}

std::optional<std::size_t> UwpTcpStream::TryWriteSome(const std::uint8_t* data, std::size_t size)
{
    streams::Buffer buffer(static_cast<std::uint32_t>(size));
    std::copy(data, data + size, buffer.data());
    buffer.Length(static_cast<std::uint32_t>(size));
    const auto written = ResultWithTimeout(m_output.WriteAsync(buffer), "tcp write", m_ioTimeout);
    m_logger.LogTrace("tcp wrote {}", written);
    return static_cast<std::size_t>(written);
}

std::optional<std::vector<std::uint8_t>> UwpTcpStream::TryReadSome(std::size_t maxBytes)
{
    if (!m_nonBlockingReads)
    {
        streams::Buffer buffer(static_cast<std::uint32_t>(maxBytes));
        auto read = m_input.ReadAsync(
            buffer, static_cast<std::uint32_t>(maxBytes), streams::InputStreamOptions::Partial);
        return BytesFromBuffer(ResultWithOptionalTimeout(read, "tcp read", m_readTimeout),
                               m_logger);
    }

    if (!m_pendingRead)
    {
        streams::Buffer buffer(static_cast<std::uint32_t>(maxBytes));
        m_pendingRead = m_input.ReadAsync(
            buffer, static_cast<std::uint32_t>(maxBytes), streams::InputStreamOptions::Partial);
    }
    if (m_pendingRead.Status() == foundation::AsyncStatus::Started)
    {
        return std::nullopt;
    }
    auto completed = std::exchange(m_pendingRead, nullptr);
    return BytesFromBuffer(completed.GetResults(), m_logger);
}

void UwpTcpStream::SetReadTimeout(std::optional<std::chrono::seconds> timeout)
{
    m_readTimeout = timeout;
}

void UwpTcpStream::SetNonBlockingReads(bool enabled)
{
    if (!enabled && m_pendingRead)
    {
        m_pendingRead.Cancel();
        m_pendingRead = nullptr;
    }
    m_nonBlockingReads = enabled;
}

void UwpTcpStream::WaitForPendingRead()
{
    if (!m_pendingRead)
    {
        return;
    }
    if (m_pendingRead.wait_for(m_ioTimeout) == foundation::AsyncStatus::Started)
    {
        m_pendingRead.Cancel();
        m_pendingRead = nullptr;
        throw std::runtime_error("TCP read timed out.");
    }
}

void UwpTcpStream::Close()
{
    m_socket.Close();
}

} // namespace tailgate::uwp
