#include "LinuxPeerApiServer.h"

#include "FdStream.h"
#include "UniqueFd.h"
#include "tailgate/ByteStream.h"
#include "tailgate/Logging.h"
#include "tailgate/serve/PeerApiIngress.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <format>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <linux/in.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{

int PeerApiWaitTimeout(const IByteStream& stream)
{
    return stream.HasBufferedInput() ? 0 : -1;
}

namespace
{

constexpr int ListenBacklog = 128;
constexpr std::size_t CopyBufferSize = 16U * 1024U;
constexpr std::size_t MaximumQueuedBytes = 4U * 1024U * 1024U;
constexpr std::size_t MaximumReadsPerCycle = 16;

void SetNonBlocking(int fd)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    {
        throw std::runtime_error("peerapi nonblocking setup failed: " +
                                 std::string(std::strerror(errno)));
    }
}

struct PendingWrites
{
    std::deque<std::vector<std::uint8_t>> Buffers;
    std::size_t Offset = 0;
    std::size_t Bytes = 0;

    void Push(std::vector<std::uint8_t> data)
    {
        Bytes += data.size();
        if (Bytes > MaximumQueuedBytes)
        {
            throw std::runtime_error("peerapi forwarding queue limit exceeded");
        }
        Buffers.push_back(std::move(data));
    }

    bool Flush(IByteStream& stream)
    {
        while (!Buffers.empty())
        {
            const std::vector<std::uint8_t>& data = Buffers.front();
            const std::optional<std::size_t> written =
                stream.TryWriteSome(data.data() + Offset, data.size() - Offset);
            if (!written)
            {
                return false;
            }
            if (*written == 0)
            {
                throw std::runtime_error("peerapi forwarding stream closed during write");
            }
            Offset += *written;
            if (Offset == data.size())
            {
                Bytes -= data.size();
                Buffers.pop_front();
                Offset = 0;
            }
        }
        return true;
    }
};

void ModifyEvents(int epollFd, int fd, std::uint32_t events, std::uint64_t tag)
{
    epoll_event event{};
    event.events = events;
    event.data.u64 = tag;
    if (epoll_ctl(epollFd, EPOLL_CTL_MOD, fd, &event) != 0)
    {
        throw std::runtime_error("peerapi epoll update failed: " +
                                 std::string(std::strerror(errno)));
    }
}

void PumpTls(int peerFd, IByteStream& tls, int localFd, IByteStream& local)
{
    constexpr std::uint64_t PeerTag = 1;
    constexpr std::uint64_t LocalTag = 2;
    SetNonBlocking(peerFd);
    SetNonBlocking(localFd);
    UniqueFd epoll(epoll_create1(EPOLL_CLOEXEC));
    if (epoll.Fd < 0)
    {
        throw std::runtime_error("peerapi epoll creation failed");
    }
    epoll_event peerEvent{EPOLLIN, {.u64 = PeerTag}};
    epoll_event localEvent{EPOLLIN, {.u64 = LocalTag}};
    if (epoll_ctl(epoll.Fd, EPOLL_CTL_ADD, peerFd, &peerEvent) != 0 ||
        epoll_ctl(epoll.Fd, EPOLL_CTL_ADD, localFd, &localEvent) != 0)
    {
        throw std::runtime_error("peerapi epoll registration failed");
    }
    PendingWrites toPeer;
    PendingWrites toLocal;
    while (true)
    {
        std::array<epoll_event, 2> events{};
        const int count =
            epoll_wait(epoll.Fd, events.data(), events.size(), PeerApiWaitTimeout(tls));
        if (count < 0 && errno == EINTR)
        {
            continue;
        }
        if (count < 0)
        {
            throw std::runtime_error("peerapi epoll wait failed");
        }
        bool peerReady = tls.HasBufferedInput() && !tls.WriteNeedsRead();
        bool localReady = false;
        for (int index = 0; index < count; ++index)
        {
            if ((events[index].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0)
            {
                return;
            }
            peerReady =
                peerReady || (events[index].data.u64 == PeerTag && !tls.WriteNeedsRead() &&
                              (((events[index].events & EPOLLIN) != 0) ||
                               (((events[index].events & EPOLLOUT) != 0) && tls.ReadNeedsWrite())));
            localReady = localReady || (events[index].data.u64 == LocalTag &&
                                        (events[index].events & (EPOLLIN | EPOLLOUT)) != 0);
        }
        if (peerReady)
        {
            for (std::size_t read = 0; read < MaximumReadsPerCycle; ++read)
            {
                std::optional<std::vector<std::uint8_t>> input = tls.TryReadSome(CopyBufferSize);
                if (!input)
                {
                    break;
                }
                if (input->empty())
                {
                    return;
                }
                toLocal.Push(std::move(*input));
            }
        }
        if (localReady)
        {
            for (std::size_t read = 0; read < MaximumReadsPerCycle; ++read)
            {
                std::optional<std::vector<std::uint8_t>> input = local.TryReadSome(CopyBufferSize);
                if (!input)
                {
                    break;
                }
                if (input->empty())
                {
                    return;
                }
                toPeer.Push(std::move(*input));
            }
        }
        if (!tls.ReadNeedsWrite())
        {
            (void)toPeer.Flush(tls);
        }
        (void)toLocal.Flush(local);
        ModifyEvents(epoll.Fd,
                     peerFd,
                     EPOLLIN | EPOLLRDHUP |
                         (toPeer.Buffers.empty() && !tls.ReadNeedsWrite() ? 0U : EPOLLOUT),
                     PeerTag);
        ModifyEvents(epoll.Fd,
                     localFd,
                     EPOLLIN | EPOLLRDHUP | (toLocal.Buffers.empty() ? 0U : EPOLLOUT),
                     LocalTag);
    }
}

void SetReuseAddress(int fd)
{
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0)
    {
        throw std::runtime_error("peerapi SO_REUSEADDR failed: " +
                                 std::string(std::strerror(errno)));
    }
}

void SetFreeBind(int fd, int family)
{
    int enabled = 1;
    const int option = family == AF_INET ? IP_FREEBIND : IPV6_FREEBIND;
    if (setsockopt(fd, family == AF_INET ? SOL_IP : SOL_IPV6, option, &enabled, sizeof(enabled)) !=
        0)
    {
        throw std::runtime_error("peerapi FREEBIND failed: " + std::string(std::strerror(errno)));
    }
}

UniqueFd ListenOn(const std::string& addressText, int port)
{
    const int family = addressText.find(':') == std::string::npos ? AF_INET : AF_INET6;
    UniqueFd listener(socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (listener.Fd < 0)
    {
        throw std::runtime_error("peerapi listener socket failed: " +
                                 std::string(std::strerror(errno)));
    }
    SetReuseAddress(listener.Fd);
    SetFreeBind(listener.Fd, family);
    if (family == AF_INET)
    {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<std::uint16_t>(port));
        if (inet_pton(AF_INET, addressText.c_str(), &address.sin_addr) != 1)
        {
            throw std::runtime_error("peerapi listen address is not IPv4: " + addressText);
        }
        if (bind(listener.Fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
        {
            throw std::runtime_error(std::format(
                "peerapi bind failed on {}:{}: {}", addressText, port, std::strerror(errno)));
        }
    }
    else
    {
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(static_cast<std::uint16_t>(port));
        if (inet_pton(AF_INET6, addressText.c_str(), &address.sin6_addr) != 1)
        {
            throw std::runtime_error("peerapi listen address is not IPv6: " + addressText);
        }
        if (bind(listener.Fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
        {
            throw std::runtime_error(std::format(
                "peerapi bind failed on [{}]:{}: {}", addressText, port, std::strerror(errno)));
        }
    }
    if (listen(listener.Fd, ListenBacklog) != 0)
    {
        throw std::runtime_error("peerapi listen failed: " + std::string(std::strerror(errno)));
    }
    return listener;
}

UniqueFd ConnectLocal(int port)
{
    UniqueFd fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (fd.Fd < 0)
    {
        throw std::runtime_error("peerapi local socket failed: " +
                                 std::string(std::strerror(errno)));
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1)
    {
        throw std::runtime_error("peerapi local address conversion failed");
    }
    if (connect(fd.Fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
    {
        throw std::runtime_error(std::format(
            "peerapi local connect failed to 127.0.0.1:{}: {}", port, std::strerror(errno)));
    }
    int noDelay = 1;
    if (setsockopt(fd.Fd, IPPROTO_TCP, TCP_NODELAY, &noDelay, sizeof(noDelay)) != 0)
    {
        throw std::runtime_error("peerapi local TCP_NODELAY failed: " +
                                 std::string(std::strerror(errno)));
    }
    return fd;
}

std::string RemoteAddress(const sockaddr_storage& remote)
{
    std::vector<char> host(NI_MAXHOST);
    std::vector<char> service(NI_MAXSERV);
    const int result =
        getnameinfo(reinterpret_cast<const sockaddr*>(&remote),
                    remote.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
                    host.data(),
                    static_cast<socklen_t>(host.size()),
                    service.data(),
                    static_cast<socklen_t>(service.size()),
                    NI_NUMERICHOST | NI_NUMERICSERV);
    if (result != 0)
    {
        return "unknown";
    }
    return std::format("{}:{}", host.data(), service.data());
}

} // namespace

class LinuxPeerApiServer::Impl
{
public:
    Impl(const std::string& tailnetAddress,
         int peerApiPort,
         std::string funnelTarget,
         int localPort,
         std::string certificatePem,
         std::string privateKeyPem)
        : m_listener(ListenOn(tailnetAddress, peerApiPort)),
          m_handler(std::move(funnelTarget), std::move(certificatePem), std::move(privateKeyPem)),
          m_localPort(localPort),
          m_thread(
              [this]()
              {
                  Run();
              })
    {
        Log(LogLevel::Info,
            "peerapi",
            std::format("listening on {}:{}", tailnetAddress, peerApiPort));
    }

    ~Impl()
    {
        m_stopping = true;
        if (m_listener.Fd >= 0)
        {
            shutdown(m_listener.Fd, SHUT_RDWR);
        }
        if (m_thread.joinable())
        {
            m_thread.join();
        }
        {
            std::lock_guard lock(m_connectionsMutex);
            for (const int fd : m_connections)
            {
                shutdown(fd, SHUT_RDWR);
            }
        }
        for (std::thread& worker : m_workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
    }

private:
    void Run()
    {
        while (!m_stopping)
        {
            sockaddr_storage remote{};
            socklen_t remoteLength = sizeof(remote);
            UniqueFd accepted(accept4(
                m_listener.Fd, reinterpret_cast<sockaddr*>(&remote), &remoteLength, SOCK_CLOEXEC));
            if (accepted.Fd < 0)
            {
                if (m_stopping || errno == EINTR)
                {
                    continue;
                }
                Log(LogLevel::Warning,
                    "peerapi",
                    "accept failed: " + std::string(std::strerror(errno)));
                continue;
            }
            const std::string remoteText = RemoteAddress(remote);
            int noDelay = 1;
            if (setsockopt(accepted.Fd, IPPROTO_TCP, TCP_NODELAY, &noDelay, sizeof(noDelay)) != 0)
            {
                Log(LogLevel::Warning,
                    "peerapi",
                    std::format("TCP_NODELAY failed for {}: {}", remoteText, std::strerror(errno)));
                continue;
            }
            Log(LogLevel::Info, "peerapi", "accepted connection from " + remoteText);
            const int connectionFd = accepted.Release();
            {
                std::lock_guard lock(m_connectionsMutex);
                m_connections.insert(connectionFd);
            }
            m_workers.emplace_back(
                [this, fd = connectionFd, remoteText]()
                {
                    UniqueFd connection(fd);
                    HandleConnection(connection.Fd, remoteText);
                    std::lock_guard lock(m_connectionsMutex);
                    m_connections.erase(fd);
                });
        }
    }

    void HandleConnection(int fd, const std::string& remoteText)
    {
        try
        {
            FdStream peer(fd);
            const tailgate::serve::PeerApiIngressRequest request =
                m_handler.ReadRequestAndRespond(peer);
            Log(LogLevel::Info,
                "peerapi",
                std::format("request from {} line={}", remoteText, request.RequestLine));
            if (request.Status == tailgate::serve::PeerApiIngressStatus::NotFound)
            {
                Log(LogLevel::Warning, "peerapi", "rejecting unknown request from " + remoteText);
                return;
            }
            if (request.Status == tailgate::serve::PeerApiIngressStatus::Forbidden)
            {
                Log(LogLevel::Warning,
                    "peerapi",
                    std::format("rejecting ingress from {} source={} target={}",
                                remoteText,
                                request.Source.empty() ? "<missing>" : request.Source,
                                request.Target.empty() ? "<missing>" : request.Target));
                return;
            }
            Log(LogLevel::Info,
                "peerapi",
                std::format("accepted ingress from {} source={} target={} local-port={}",
                            remoteText,
                            request.Source,
                            request.Target,
                            m_localPort));
            UniqueFd local = ConnectLocal(m_localPort);
            FdStream localStream(local.Fd);
            std::unique_ptr<IByteStream> tls = m_handler.OpenTlsStream(peer);
            PumpTls(fd, *tls, local.Fd, localStream);
        }
        catch (const std::exception& error)
        {
            Log(LogLevel::Warning, "peerapi", "ingress failed: " + std::string(error.what()));
        }
    }

    UniqueFd m_listener;
    tailgate::serve::PeerApiIngressHandler m_handler;
    int m_localPort = 0;
    std::atomic<bool> m_stopping = false;
    std::thread m_thread;
    std::mutex m_connectionsMutex;
    std::unordered_set<int> m_connections;
    std::vector<std::thread> m_workers;
};

LinuxPeerApiServer::LinuxPeerApiServer(const std::string& tailnetAddress,
                                       int peerApiPort,
                                       std::string funnelTarget,
                                       int localPort,
                                       std::string certificatePem,
                                       std::string privateKeyPem)
    : m_impl(std::make_unique<Impl>(tailnetAddress,
                                    peerApiPort,
                                    std::move(funnelTarget),
                                    localPort,
                                    std::move(certificatePem),
                                    std::move(privateKeyPem)))
{
}

LinuxPeerApiServer::~LinuxPeerApiServer() = default;

} // namespace tailgate::linux_frontend
