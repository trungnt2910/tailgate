#include "DialOperation.h"

#include <chrono>
#include <utility>

namespace tailgate::derp::impl
{

DialOperation::DialOperation(ConnectionOptions options,
                             std::shared_ptr<types::nettype::TcpSocketFactory> sockets,
                             std::shared_ptr<base::EventLoop> events)
    : m_worker(
          [this,
           options = std::move(options),
           sockets = std::move(sockets),
           events = std::move(events)](std::stop_token cancellation)
          {
              DialResult result;
              try
              {
                  constexpr std::chrono::seconds HandshakeIoTimeout{20};
                  types::nettype::TcpSocketOptions transport;
                  transport.ConnectAddress = options.Host;
                  transport.Service = "443";
                  if (!options.NetworkInterface.empty())
                  {
                      transport.NetworkInterface = options.NetworkInterface;
                  }
                  transport.TlsServerName = options.Host;
                  transport.IoTimeout = HandshakeIoTimeout;
                  transport.ReadinessToken = options.ReadinessToken;
                  transport.Cancellation = cancellation;
                  transport.ReadinessEvents = *events;
                  result.Socket = sockets->OpenTcpSocket(transport);
                  result.Client =
                      options.Authenticator
                          ? std::make_unique<DerpClient>(*result.Socket, *options.Authenticator)
                          : std::make_unique<DerpClient>(
                                *result.Socket, options.PrivateKey, options.PublicKey);
                  result.Client->Connect(options.Host, cancellation);
                  result.Client->SetPreferred(options.Preferred);
                  result.Client->Flush();
              }
              catch (...)
              {
                  result.Client.reset();
                  result.Socket.reset();
                  result.Error = std::current_exception();
              }
              {
                  std::lock_guard lock(m_mutex);
                  m_result = std::move(result);
              }
              events->Post(base::Event{.Token = options.ReadinessToken,
                                       .Readiness = base::EventReadiness::None});
          })
{
}

DialOperation::~DialOperation() = default;

std::optional<DialResult> DialOperation::TakeResult()
{
    std::optional<DialResult> result;
    {
        std::lock_guard lock(m_mutex);
        if (!m_result)
        {
            return std::nullopt;
        }
        result = std::move(m_result);
        m_result.reset();
    }
    // The worker has completed network I/O; joining only synchronizes completion.
    m_worker.join();
    return result;
}

} // namespace tailgate::derp::impl
