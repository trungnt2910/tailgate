#include "PeerTransport.h"

#include <algorithm>
#include <exception>

#include <tailgate/net/http/Message.h>

namespace tailgate::drive::driveimpl
{

PeerTransport::PeerTransport(wgengine::netstack::Stack& stack, base::TimeProvider& time) noexcept
    : m_stack(stack), m_time(time)
{
}

PeerTransport::~PeerTransport()
{
    Stop();
}

bool PeerTransport::Allowed(const Remote& remote) const
{
    return m_catalog && m_catalog->Access &&
           std::ranges::find(m_catalog->Remotes, remote) != m_catalog->Remotes.end();
}

void PeerTransport::SetCatalog(std::shared_ptr<const Catalog> catalog)
{
    if (m_catalog &&
        (m_catalog->SelfKey != catalog->SelfKey || m_catalog->Domain != catalog->Domain))
    {
        Stop();
    }
    m_catalog = std::move(catalog);
    std::erase_if(m_idle,
                  [&](auto& connection)
                  {
                      if (Allowed(connection.Peer))
                      {
                          return false;
                      }
                      connection.Stream->Abort();
                      return true;
                  });
}

bool PeerTransport::Healthy(wgengine::netstack::Stream& stream) noexcept
{
    try
    {
        // An idle HTTP connection cannot legitimately receive another response before
        // a request. Both EOF and unsolicited bytes prohibit reuse (response poisoning).
        return stream.State() == wgengine::netstack::StreamState::Open &&
               !stream.TryReadSome(1).has_value();
    }
    catch (const std::exception&)
    {
        return false;
    }
}

void PeerTransport::Close(wgengine::netstack::Stream& stream) noexcept
{
    try
    {
        if (stream.TryClose())
        {
            return;
        }
    }
    catch (const std::exception&)
    {
        // Best-effort graceful disposal falls back to Abort below; cleanup cannot throw.
    }
    stream.Abort();
}

std::unique_ptr<wgengine::netstack::Stream> PeerTransport::Acquire(const Remote& remote)
{
    if (!Allowed(remote))
    {
        throw net::http::MessageError(net::http::MessageErrorKind::InvalidState);
    }
    (void)Poll();
    const auto found = std::ranges::find(m_idle, remote, &IdleConnection::Peer);
    if (found != m_idle.end())
    {
        auto stream = std::move(found->Stream);
        m_idle.erase(found);
        return stream;
    }
    return m_stack.Connect(wgengine::netstack::TcpEndpoint{
        .Address = remote.Ipv4 ? *remote.Ipv4 : *remote.Ipv6,
        .Port = remote.Ipv4 ? remote.PeerApi4Port : remote.PeerApi6Port});
}

void PeerTransport::Release(const Remote& remote,
                            std::unique_ptr<wgengine::netstack::Stream> stream)
{
    if (!Allowed(remote) || !Healthy(*stream))
    {
        stream->Abort();
        return;
    }
    const auto count =
        static_cast<std::size_t>(std::ranges::count(m_idle, remote, &IdleConnection::Peer));
    if (m_idle.size() >= MaximumIdleConnections || count >= MaximumIdlePerPeer)
    {
        Close(*stream);
        return;
    }
    m_idle.push_back(IdleConnection{
        .Peer = remote, .Stream = std::move(stream), .Deadline = m_time.Now() + IdleTimeout});
}

bool PeerTransport::Poll()
{
    return std::erase_if(m_idle,
                         [&](auto& connection)
                         {
                             if (!Healthy(*connection.Stream))
                             {
                                 connection.Stream->Abort();
                                 return true;
                             }
                             if (m_time.Now() >= connection.Deadline)
                             {
                                 Close(*connection.Stream);
                                 return true;
                             }
                             return false;
                         }) != 0;
}

std::optional<base::TimeProvider::TimePoint> PeerTransport::NextDeadline() const
{
    if (m_idle.empty())
    {
        return std::nullopt;
    }
    return std::ranges::min_element(m_idle, {}, &IdleConnection::Deadline)->Deadline;
}

void PeerTransport::Stop() noexcept
{
    for (auto& connection : m_idle)
    {
        connection.Stream->Abort();
    }
    m_idle.clear();
    m_catalog.reset();
}

} // namespace tailgate::drive::driveimpl
