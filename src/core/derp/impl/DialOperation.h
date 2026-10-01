#pragma once

#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

#include <tailgate/base/EventLoop.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::derp::impl
{

struct DialResult
{
    // The client borrows the socket, so it must be destroyed first.
    std::unique_ptr<types::nettype::TcpSocket> Socket;
    std::unique_ptr<DerpClient> Client;
    std::exception_ptr Error;
};

// One attempt owns all handshake state. Cancellation wakes blocking platform waits;
// destruction joins before releasing the factory, event loop or authenticator.
class DialOperation final
{
public:
    DialOperation(ConnectionOptions options,
                  std::shared_ptr<types::nettype::TcpSocketFactory> sockets,
                  std::shared_ptr<base::EventLoop> events);
    ~DialOperation();
    [[nodiscard]] std::optional<DialResult> TakeResult();

private:
    std::mutex m_mutex;
    std::optional<DialResult> m_result;
    std::jthread m_worker;
};

} // namespace tailgate::derp::impl
