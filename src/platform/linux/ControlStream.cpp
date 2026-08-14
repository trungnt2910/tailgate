#include "ControlStream.h"

#include <utility>

#include <tailgate/base/Logging.h>
#include <tailgate/control/base/ControlHandshake.h>
#include <tailgate/control/client/ControlDialer.h>

#include "LinuxCaBundle.h"

namespace tailgate::linux_frontend
{
namespace
{

constexpr int PlaintextControlConnectTimeoutSeconds = 5;

} // namespace

ControlStream::ControlStream(const std::string& interfaceName, bool useTls)
    : m_transport(tailgate::control::base::ControlHandshake::DefaultHost,
                  useTls ? tailgate::control::base::ControlHandshake::TlsService
                         : tailgate::control::base::ControlHandshake::PlaintextService,
                  interfaceName,
                  TcpStream::ControlIoTimeoutSeconds,
                  useTls ? 0 : PlaintextControlConnectTimeoutSeconds)
{
    if (useTls)
    {
        m_tls = std::make_unique<tailgate::net::tls::TlsStream>(
            m_transport, tailgate::control::base::ControlHandshake::DefaultHost, SystemCaBundle());
    }
}

tailgate::base::IByteStream& ControlStream::Active()
{
    return m_tls ? static_cast<tailgate::base::IByteStream&>(*m_tls) : m_transport;
}

const tailgate::base::IByteStream& ControlStream::Active() const
{
    return m_tls ? static_cast<const tailgate::base::IByteStream&>(*m_tls) : m_transport;
}

std::optional<std::size_t> ControlStream::TryWriteSome(const std::uint8_t* data, std::size_t size)
{
    return Active().TryWriteSome(data, size);
}

std::optional<std::vector<std::uint8_t>> ControlStream::TryReadSome(std::size_t maxBytes)
{
    return Active().TryReadSome(maxBytes);
}

bool ControlStream::HasBufferedInput() const
{
    return Active().HasBufferedInput();
}

bool ControlStream::ReadNeedsWrite() const
{
    return Active().ReadNeedsWrite();
}

bool ControlStream::WriteNeedsRead() const
{
    return Active().WriteNeedsRead();
}

int ControlStream::NativeHandle() const
{
    return m_transport.NativeHandle();
}

void ControlStream::SetNonBlocking(bool enabled)
{
    m_transport.SetNonBlocking(enabled);
}

DialedControlStream DialControl(const std::string& interfaceName,
                                const std::function<void(tailgate::base::IByteStream&)>& establish)
{
    tailgate::control::client::ControlDialOutcome<std::unique_ptr<ControlStream>> outcome =
        tailgate::control::client::DialControlStream(
            [&interfaceName]()
            {
                return std::make_unique<ControlStream>(interfaceName, false);
            },
            [&interfaceName]()
            {
                return std::make_unique<ControlStream>(interfaceName, true);
            },
            establish);
    tailgate::base::Log(tailgate::base::LogLevel::Info,
                        "control",
                        outcome.UsedTls ? "control connected through the TLS fallback"
                                        : "control connected through plaintext ts2021");
    return DialedControlStream{.Stream = std::move(outcome.Stream), .UsedTls = outcome.UsedTls};
}

} // namespace tailgate::linux_frontend
