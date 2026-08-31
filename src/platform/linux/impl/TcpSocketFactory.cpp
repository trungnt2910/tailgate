#include "TcpSocketFactory.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <poll.h>

#include <tailgate/base/ByteStream.h>
#include <tailgate/net/tls/TlsStream.h>

#include "SocketIo.h"
#include "TcpStream.h"

namespace tailgate::linux_frontend::impl
{
namespace
{

class CaBundleNotFound final : public std::runtime_error
{
public:
    CaBundleNotFound() : std::runtime_error("no system CA bundle was found")
    {
    }
};

std::vector<std::uint8_t> SystemCaBundle()
{
    static constexpr std::array<const char*, 5> Candidates = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/ssl/cert.pem",
    };
    std::filesystem::path path;
    for (const char* candidate : Candidates)
    {
        if (std::filesystem::is_regular_file(candidate))
        {
            path = candidate;
            break;
        }
    }
    if (path.empty())
    {
        throw CaBundleNotFound();
    }
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
    {
        throw std::filesystem::filesystem_error(
            "failed to open system CA bundle", path, std::make_error_code(std::errc::io_error));
    }
    return {
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>(),
    };
}

class TcpSocket final : public tailgate::types::nettype::TcpSocket
{
public:
    TcpSocket(const tailgate::types::nettype::TcpSocketOptions& options,
              std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistry)
        : m_transport(std::make_unique<TcpStream>(
              options.ConnectAddress,
              options.Service,
              options.NetworkInterface.value_or(std::string{}),
              static_cast<int>(options.IoTimeout.count()),
              static_cast<int>(options.ConnectTimeout.value_or(std::chrono::seconds{}).count()))),
          m_eventRegistry(std::move(eventRegistry)),
          m_readinessToken(options.ReadinessToken),
          m_ioTimeout(options.IoTimeout),
          m_nonBlocking(options.NonBlockingAfterConnect)
    {
        if (options.TlsServerName)
        {
            m_tls = std::make_unique<tailgate::net::tls::TlsStream>(
                *m_transport, *options.TlsServerName, SystemCaBundle(), options.AllowTls13);
        }
        if (options.NonBlockingAfterConnect)
        {
            m_transport->SetNonBlocking(true);
        }
        if (m_nonBlocking)
        {
            RegisterForEvents();
        }
    }

    ~TcpSocket() override
    {
        Close();
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        return detail::CompleteSocketIo<std::size_t>(
            m_nonBlocking,
            [&]()
            {
                return ActiveStream().TryWriteSome(data, size);
            },
            [&]()
            {
                WaitFor(ActiveStream().WriteNeedsRead() ? POLLIN : POLLOUT);
            });
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maximumSize) override
    {
        return detail::CompleteSocketIo<std::vector<std::uint8_t>>(
            m_nonBlocking,
            [&]()
            {
                return ActiveStream().TryReadSome(maximumSize);
            },
            [&]()
            {
                WaitFor(ActiveStream().ReadNeedsWrite() ? POLLOUT : POLLIN);
            });
    }

    bool HasBufferedInput() const override
    {
        return ActiveStream().HasBufferedInput();
    }

    bool ReadNeedsWrite() const override
    {
        return ActiveStream().ReadNeedsWrite();
    }

    bool WriteNeedsRead() const override
    {
        return ActiveStream().WriteNeedsRead();
    }

    void SetReadTimeout(std::optional<std::chrono::seconds> timeout) override
    {
        m_transport->SetReadTimeout(timeout);
    }

    void SetWriteInterest(bool enabled) override
    {
        if (m_readinessToken.Value == 0 || m_writeInterest == enabled)
        {
            return;
        }
        m_writeInterest = enabled;
        if (m_eventRegistered)
        {
            m_eventHandle.Modify(EventInterest());
        }
    }

    void SetNonBlocking(bool enabled) override
    {
        m_transport->SetNonBlocking(enabled);
        m_nonBlocking = enabled;
        if (enabled)
        {
            RegisterForEvents();
        }
        else
        {
            m_eventHandle.Reset();
            m_eventRegistered = false;
        }
    }

    void Close() noexcept override
    {
        m_eventHandle.Reset();
        m_eventRegistered = false;
        m_tls.reset();
        m_transport.reset();
    }

private:
    [[nodiscard]] tailgate::linux_frontend::event::EventInterest EventInterest() const noexcept
    {
        using tailgate::linux_frontend::event::EventInterest;
        return m_writeInterest ? EventInterest::Readable | EventInterest::Writable
                               : EventInterest::Readable;
    }

    void RegisterForEvents()
    {
        if (m_eventRegistered || m_readinessToken.Value == 0)
        {
            return;
        }
        m_eventHandle = m_eventRegistry->Register(
            m_transport->NativeHandle(), EventInterest(), m_readinessToken);
        m_eventRegistered = true;
    }

    void WaitFor(short events)
    {
        pollfd descriptor{.fd = m_transport->NativeHandle(), .events = events, .revents = 0};
        int result = 0;
        do
        {
            result = poll(&descriptor, 1, static_cast<int>(m_ioTimeout.count() * 1000));
        } while (result < 0 && errno == EINTR);
        if (result == 0)
        {
            throw std::system_error(std::make_error_code(std::errc::timed_out));
        }
        if (result < 0)
        {
            throw std::system_error(errno, std::generic_category());
        }
    }

    [[nodiscard]] tailgate::base::ByteStream& ActiveStream()
    {
        return m_tls ? static_cast<tailgate::base::ByteStream&>(*m_tls)
                     : static_cast<tailgate::base::ByteStream&>(*m_transport);
    }

    [[nodiscard]] const tailgate::base::ByteStream& ActiveStream() const
    {
        return m_tls ? static_cast<const tailgate::base::ByteStream&>(*m_tls)
                     : static_cast<const tailgate::base::ByteStream&>(*m_transport);
    }

    std::unique_ptr<TcpStream> m_transport;
    std::unique_ptr<tailgate::net::tls::TlsStream> m_tls;
    std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> m_eventRegistry;
    tailgate::linux_frontend::event::EventHandle m_eventHandle;
    tailgate::base::EventToken m_readinessToken;
    std::chrono::seconds m_ioTimeout;
    bool m_nonBlocking = false;
    bool m_writeInterest = false;
    bool m_eventRegistered = false;
};

} // namespace

TcpSocketFactory::TcpSocketFactory(
    std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistry)
    : m_eventRegistry(std::move(eventRegistry))
{
}

std::unique_ptr<tailgate::types::nettype::TcpSocket>
TcpSocketFactory::OpenTcpSocket(const tailgate::types::nettype::TcpSocketOptions& options)
{
    return std::make_unique<TcpSocket>(options, m_eventRegistry);
}

} // namespace tailgate::linux_frontend::impl
