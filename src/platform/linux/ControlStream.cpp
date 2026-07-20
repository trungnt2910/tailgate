#include "ControlStream.h"

#include <utility>

#include <tailgate/Logging.h>
#include <tailgate/control/ControlDialer.h>
#include <tailgate/protocol/ControlHandshake.h>

#include "LinuxCaBundle.h"

namespace tailgate::linux_frontend
{
namespace
{

constexpr int PlaintextControlConnectTimeoutSeconds = 5;

} // namespace

ControlStream::ControlStream(const std::string& interfaceName, bool useTls)
    : m_transport(protocol::ControlHandshake::DefaultHost,
                  useTls ? protocol::ControlHandshake::TlsService
                         : protocol::ControlHandshake::PlaintextService,
                  interfaceName,
                  TcpStream::ControlIoTimeoutSeconds,
                  useTls ? 0 : PlaintextControlConnectTimeoutSeconds)
{
    if (useTls)
    {
        m_tls = std::make_unique<protocol::TlsStream>(
            m_transport, protocol::ControlHandshake::DefaultHost, SystemCaBundle());
    }
}

IByteStream& ControlStream::Active()
{
    return m_tls ? static_cast<IByteStream&>(*m_tls) : m_transport;
}

const IByteStream& ControlStream::Active() const
{
    return m_tls ? static_cast<const IByteStream&>(*m_tls) : m_transport;
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
                                const std::function<void(IByteStream&)>& establish)
{
    control::ControlDialOutcome<std::unique_ptr<ControlStream>> outcome =
        control::DialControlStream(
            [&interfaceName]()
            {
                return std::make_unique<ControlStream>(interfaceName, false);
            },
            [&interfaceName]()
            {
                return std::make_unique<ControlStream>(interfaceName, true);
            },
            establish);
    Log(LogLevel::Info,
        "control",
        outcome.UsedTls ? "control connected through the TLS fallback"
                        : "control connected through plaintext ts2021");
    return DialedControlStream{.Stream = std::move(outcome.Stream), .UsedTls = outcome.UsedTls};
}

} // namespace tailgate::linux_frontend
