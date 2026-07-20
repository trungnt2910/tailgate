#include "LinuxRelayServer.h"

#include "FdStream.h"
#include "UniqueFd.h"
#include "tailgate/Logging.h"
#include "tailgate/relay/RelayProtocol.h"
#include "tailgate/serve/HandshakeLimiter.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <format>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{
namespace
{

constexpr int ListenBacklog = 64;
constexpr std::size_t MaximumConnections = 64;
constexpr std::size_t MaximumPendingHandshakes = 16;
constexpr std::size_t HandshakeBurst = 16;
constexpr std::chrono::milliseconds HandshakeRefillInterval(250);
constexpr std::chrono::seconds AuthenticationTimeout(15);

UniqueFd Listen(int port)
{
    UniqueFd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (listener.Fd < 0)
    {
        throw std::runtime_error("relay listener socket failed: " +
                                 std::string(std::strerror(errno)));
    }
    int enabled = 1;
    if (setsockopt(listener.Fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0)
    {
        throw std::runtime_error("relay SO_REUSEADDR failed: " + std::string(std::strerror(errno)));
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener.Fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
    {
        throw std::runtime_error(
            std::format("relay bind failed on 127.0.0.1:{}: {}", port, std::strerror(errno)));
    }
    if (listen(listener.Fd, ListenBacklog) != 0)
    {
        throw std::runtime_error("relay listen failed: " + std::string(std::strerror(errno)));
    }
    return listener;
}

} // namespace

class LinuxRelayServer::Impl
{
public:
    Impl(int port, Handler handler)
        : m_listener(Listen(port)),
          m_handler(std::move(handler)),
          m_thread(
              [this]()
              {
                  Run();
              })
    {
        Log(LogLevel::Info, "relay", std::format("listening on 127.0.0.1:{}", port));
    }

    ~Impl()
    {
        m_stopping = true;
        shutdown(m_listener.Fd, SHUT_RDWR);
        if (m_thread.joinable())
        {
            m_thread.join();
        }
        {
            std::lock_guard lock(m_connectionMutex);
            for (int fd : m_connectionFds)
            {
                shutdown(fd, SHUT_RDWR);
            }
        }
        for (Connection& connection : m_connections)
        {
            if (connection.Worker.joinable())
            {
                connection.Worker.join();
            }
        }
    }

private:
    struct Connection
    {
        std::thread Worker;
        std::shared_ptr<std::atomic_bool> Completed;
    };

    void ReapConnections()
    {
        std::lock_guard lock(m_connectionMutex);
        m_connections.erase(std::remove_if(m_connections.begin(),
                                           m_connections.end(),
                                           [](Connection& connection)
                                           {
                                               if (!*connection.Completed)
                                               {
                                                   return false;
                                               }
                                               if (connection.Worker.joinable())
                                               {
                                                   connection.Worker.join();
                                               }
                                               return true;
                                           }),
                            m_connections.end());
    }

    void Run()
    {
        while (!m_stopping)
        {
            UniqueFd connection(accept4(m_listener.Fd, nullptr, nullptr, SOCK_CLOEXEC));
            if (connection.Fd < 0)
            {
                if (m_stopping || errno == EINTR)
                {
                    continue;
                }
                Log(LogLevel::Warning,
                    "relay",
                    "accept failed: " + std::string(std::strerror(errno)));
                continue;
            }
            ReapConnections();
            const int fd = connection.Release();
            int noDelay = 1;
            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &noDelay, sizeof(noDelay)) != 0)
            {
                Log(LogLevel::Warning,
                    "relay",
                    "TCP_NODELAY failed: " + std::string(std::strerror(errno)));
                close(fd);
                continue;
            }
            {
                std::lock_guard lock(m_connectionMutex);
                if (m_connectionFds.size() >= MaximumConnections)
                {
                    Log(LogLevel::Warning, "relay", "connection limit reached");
                    close(fd);
                    continue;
                }
                if (!m_handshakeLimiter.TryBegin())
                {
                    Log(LogLevel::Debug, "relay", "unauthenticated connection limit reached");
                    close(fd);
                    continue;
                }
                m_connectionFds.push_back(fd);
                const auto completed = std::make_shared<std::atomic_bool>(false);
                m_connections.push_back(Connection{.Worker = std::thread(
                                                       [this, fd, completed]()
                                                       {
                                                           Handle(fd);
                                                           *completed = true;
                                                       }),
                                                   .Completed = completed});
            }
        }
    }

    void Handle(int fd)
    {
        UniqueFd connection(fd);
        bool handshakePending = true;
        const auto finishHandshake = [this, &handshakePending]()
        {
            if (!handshakePending)
            {
                return;
            }
            std::lock_guard lock(m_connectionMutex);
            m_handshakeLimiter.Finish();
            handshakePending = false;
        };
        try
        {
            FdStream stream(fd);
            stream.SetReadTimeout(AuthenticationTimeout);
            relay::AcceptHttpUpgrade(stream);
            m_handler(
                stream,
                [fd]()
                {
                    shutdown(fd, SHUT_RDWR);
                },
                [&stream, finishHandshake]()
                {
                    stream.ClearReadTimeout();
                    finishHandshake();
                });
        }
        catch (const std::exception& error)
        {
            if (!m_stopping)
            {
                Log(LogLevel::Warning, "relay", "connection failed: " + std::string(error.what()));
            }
        }
        finishHandshake();
        std::lock_guard lock(m_connectionMutex);
        const auto found = std::find(m_connectionFds.begin(), m_connectionFds.end(), fd);
        if (found != m_connectionFds.end())
        {
            m_connectionFds.erase(found);
        }
    }

    UniqueFd m_listener;
    Handler m_handler;
    std::atomic<bool> m_stopping = false;
    std::thread m_thread;
    std::mutex m_connectionMutex;
    std::vector<int> m_connectionFds;
    std::vector<Connection> m_connections;
    serve::HandshakeLimiter m_handshakeLimiter{
        MaximumPendingHandshakes, HandshakeBurst, HandshakeRefillInterval};
};

LinuxRelayServer::LinuxRelayServer(int port, Handler handler)
    : m_impl(std::make_unique<Impl>(port, std::move(handler)))
{
}

LinuxRelayServer::~LinuxRelayServer() = default;

} // namespace tailgate::linux_frontend
