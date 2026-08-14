#include "LinuxDerpWorker.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <format>
#include <mutex>
#include <stdexcept>
#include <thread>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <tailgate/base/Logging.h>
#include <tailgate/derp/SendQueue.h>
#include <tailgate/net/tls/TlsStream.h>

#include "LinuxCaBundle.h"
#include "LinuxFiles.h"
#include "TcpStream.h"
#include "UniqueFd.h"

namespace tailgate::linux_frontend
{
namespace
{

enum class DerpEventKind : std::uint32_t
{
    Transport,
    Command,
    Reconnect,
};

constexpr std::chrono::seconds InitialReconnectDelay(1);
constexpr std::chrono::seconds MaximumReconnectDelay(30);
constexpr std::size_t MaximumQueuedPackets = 4096;
constexpr std::size_t MaximumQueuedBytes = 8U * 1024U * 1024U;
constexpr std::size_t MaximumFramesPerFlush = 64;

class EventCounter
{
public:
    EventCounter() : m_fd(eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC))
    {
        if (m_fd < 0)
        {
            throw std::runtime_error("eventfd failed: " + std::string(std::strerror(errno)));
        }
    }

    ~EventCounter()
    {
        if (m_fd >= 0)
        {
            close(m_fd);
        }
    }

    EventCounter(const EventCounter&) = delete;
    EventCounter& operator=(const EventCounter&) = delete;

    [[nodiscard]] int Fd() const
    {
        return m_fd;
    }

    void Notify() const
    {
        std::uint64_t value = 1;
        const ssize_t written = write(m_fd, &value, sizeof(value));
        if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            throw std::runtime_error("eventfd notify failed: " + std::string(std::strerror(errno)));
        }
    }

    void Drain() const
    {
        std::uint64_t value = 0;
        while (read(m_fd, &value, sizeof(value)) == sizeof(value))
        {
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            throw std::runtime_error("eventfd drain failed: " + std::string(std::strerror(errno)));
        }
    }

private:
    int m_fd = -1;
};

void AddEpollInterest(int epollFd, int fd, std::uint32_t events, DerpEventKind kind)
{
    epoll_event event{};
    event.events = events;
    event.data.u32 = static_cast<std::uint32_t>(kind);
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &event) != 0)
    {
        throw std::runtime_error("DERP epoll add failed: " + std::string(std::strerror(errno)));
    }
}

void ModifyEpollInterest(int epollFd, int fd, std::uint32_t events, DerpEventKind kind)
{
    epoll_event event{};
    event.events = events;
    event.data.u32 = static_cast<std::uint32_t>(kind);
    if (epoll_ctl(epollFd, EPOLL_CTL_MOD, fd, &event) != 0)
    {
        throw std::runtime_error("DERP epoll modify failed: " + std::string(std::strerror(errno)));
    }
}

} // namespace

class DerpWorker::Impl
{
public:
    Impl(const std::string& host,
         const std::string& interfaceName,
         const tailgate::crypto::Bytes32& privateKey,
         const tailgate::crypto::Bytes32& publicKey,
         bool preferred,
         tailgate::derp::DerpClient::Authenticator authenticator)
        : m_host(host),
          m_interfaceName(interfaceName),
          m_privateKey(privateKey),
          m_publicKey(publicKey),
          m_preferred(preferred),
          m_authenticator(std::move(authenticator))
    {
        m_thread = std::thread(
            [this]()
            {
                Run();
            });
    }

    ~Impl()
    {
        m_stopping = true;
        try
        {
            m_command.Notify();
        }
        catch (...)
        {
        }
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    [[nodiscard]] int NotifyFd() const
    {
        return m_notify.Fd();
    }

    void Send(const Key& destination, std::vector<std::uint8_t> packet, Priority priority)
    {
        tailgate::derp::DerpSendQueue::PushResult pushed;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            pushed =
                m_outgoing.Push(tailgate::derp::DerpSendQueue::Packet{.Destination = destination,
                                                                      .Payload = std::move(packet)},
                                priority);
        }
        if (!pushed.Accepted)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "derp",
                                "dropping oversized queued packet for " + m_host);
            return;
        }
        if (pushed.DroppedPackets != 0)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "derp",
                                std::format("queue limit reached for {}; dropped={}",
                                            m_host,
                                            pushed.DroppedPackets));
        }
        m_command.Notify();
    }

    std::vector<Packet> ReceivePackets()
    {
        m_notify.Drain();
        std::vector<Packet> result;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            result.swap(m_incoming);
        }
        return result;
    }

private:
    void Run()
    {
        UniqueFd epollFd(epoll_create1(EPOLL_CLOEXEC));
        if (epollFd.Fd < 0)
        {
            tailgate::base::Log(
                tailgate::base::LogLevel::Error,
                "derp",
                std::format("epoll_create1 failed for {}: {}", m_host, std::strerror(errno)));
            return;
        }
        try
        {
            AddEpollInterest(epollFd.Fd, m_command.Fd(), EPOLLIN, DerpEventKind::Command);
        }
        catch (const std::exception& error)
        {
            tailgate::base::Log(
                tailgate::base::LogLevel::Error,
                "derp",
                std::format("worker setup failed for {}: {}", m_host, error.what()));
            return;
        }

        std::chrono::seconds reconnectDelay = InitialReconnectDelay;
        while (!m_stopping)
        {
            try
            {
                Connect();
                reconnectDelay = InitialReconnectDelay;
                ProcessConnection(epollFd.Fd);
            }
            catch (const std::exception& error)
            {
                if (!m_stopping)
                {
                    tailgate::base::Log(
                        tailgate::base::LogLevel::Warning,
                        "derp",
                        std::format("connection to {} failed: {}; retrying in {} seconds",
                                    m_host,
                                    error.what(),
                                    reconnectDelay.count()));
                }
            }
            Disconnect();
            if (!m_stopping)
            {
                try
                {
                    WaitForReconnect(epollFd.Fd, reconnectDelay);
                }
                catch (const std::exception& error)
                {
                    tailgate::base::Log(tailgate::base::LogLevel::Error,
                                        "derp",
                                        std::format("reconnect scheduling failed for {}: {}",
                                                    m_host,
                                                    error.what()));
                    return;
                }
                reconnectDelay = std::min(reconnectDelay * 2, MaximumReconnectDelay);
            }
        }
    }

    void Connect()
    {
        m_transport = std::make_unique<TcpStream>(m_host, "443", m_interfaceName);
        m_tls =
            std::make_unique<tailgate::net::tls::TlsStream>(*m_transport, m_host, SystemCaBundle());
        m_derp =
            m_authenticator
                ? std::make_unique<tailgate::derp::DerpClient>(*m_tls, m_authenticator)
                : std::make_unique<tailgate::derp::DerpClient>(*m_tls, m_privateKey, m_publicKey);
        m_derp->Connect(m_host);
        m_derp->SetPreferred(m_preferred);
        m_transport->SetNonBlocking(true);
    }

    void Disconnect()
    {
        m_derp.reset();
        m_tls.reset();
        m_transport.reset();
    }

    void ProcessConnection(int epollFd)
    {
        std::uint32_t transportEvents = EPOLLIN;
        AddEpollInterest(
            epollFd, m_transport->NativeHandle(), transportEvents, DerpEventKind::Transport);
        while (!m_stopping)
        {
            FlushOutgoing();
            const std::uint32_t desiredTransportEvents =
                m_derp->HasPendingOutput() || m_tls->ReadNeedsWrite()
                    ? static_cast<std::uint32_t>(EPOLLIN | EPOLLOUT)
                    : static_cast<std::uint32_t>(EPOLLIN);
            if (desiredTransportEvents != transportEvents)
            {
                ModifyEpollInterest(epollFd,
                                    m_transport->NativeHandle(),
                                    desiredTransportEvents,
                                    DerpEventKind::Transport);
                transportEvents = desiredTransportEvents;
            }
            if (m_derp->HasBufferedInput())
            {
                DrainIncoming();
                continue;
            }

            epoll_event events[2]{};
            const int selected = epoll_wait(epollFd, events, 2, -1);
            if (selected < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                throw std::runtime_error("DERP epoll_wait failed: " +
                                         std::string(std::strerror(errno)));
            }
            for (int index = 0; index < selected; ++index)
            {
                const DerpEventKind kind = static_cast<DerpEventKind>(events[index].data.u32);
                if (kind == DerpEventKind::Command && (events[index].events & EPOLLIN) != 0)
                {
                    m_command.Drain();
                    FlushOutgoing();
                }
                else if (kind == DerpEventKind::Transport)
                {
                    if ((events[index].events & (EPOLLERR | EPOLLHUP)) != 0)
                    {
                        throw std::runtime_error("DERP connection closed");
                    }
                    if ((events[index].events & EPOLLOUT) != 0)
                    {
                        if (m_tls->ReadNeedsWrite())
                        {
                            DrainIncoming();
                        }
                        if (!m_tls->ReadNeedsWrite() && m_derp->HasPendingOutput())
                        {
                            m_derp->Flush();
                        }
                    }
                    if ((events[index].events & EPOLLIN) != 0 || m_derp->HasBufferedInput())
                    {
                        if (m_derp->HasPendingOutput() && m_tls->WriteNeedsRead())
                        {
                            m_derp->Flush();
                        }
                        if (!m_tls->WriteNeedsRead())
                        {
                            DrainIncoming();
                        }
                    }
                }
            }
        }
    }

    void WaitForReconnect(int epollFd, std::chrono::seconds delay)
    {
        UniqueFd timer(timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
        if (timer.Fd < 0)
        {
            throw std::runtime_error("DERP reconnect timer creation failed: " +
                                     std::string(std::strerror(errno)));
        }
        itimerspec timeout{};
        timeout.it_value.tv_sec = delay.count();
        if (timerfd_settime(timer.Fd, 0, &timeout, nullptr) != 0)
        {
            throw std::runtime_error("DERP reconnect timer setup failed: " +
                                     std::string(std::strerror(errno)));
        }
        AddEpollInterest(epollFd, timer.Fd, EPOLLIN, DerpEventKind::Reconnect);
        while (!m_stopping)
        {
            epoll_event events[2]{};
            const int selected = epoll_wait(epollFd, events, 2, -1);
            if (selected < 0 && errno == EINTR)
            {
                continue;
            }
            if (selected < 0)
            {
                throw std::runtime_error("DERP reconnect wait failed: " +
                                         std::string(std::strerror(errno)));
            }
            for (int index = 0; index < selected; ++index)
            {
                const DerpEventKind kind = static_cast<DerpEventKind>(events[index].data.u32);
                if (kind == DerpEventKind::Command)
                {
                    m_command.Drain();
                }
                else if (kind == DerpEventKind::Reconnect)
                {
                    return;
                }
            }
        }
    }

    void FlushOutgoing()
    {
        for (std::size_t frame = 0; frame < MaximumFramesPerFlush && !m_derp->HasPendingOutput();
             ++frame)
        {
            std::optional<tailgate::derp::DerpSendQueue::Packet> outgoing;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                outgoing = m_outgoing.Pop();
            }
            if (!outgoing)
            {
                return;
            }
            m_derp->Send(outgoing->Destination, outgoing->Payload);
        }
    }

    void DrainIncoming()
    {
        std::vector<Packet> packets = m_derp->ReceiveAvailableBatch();
        if (packets.empty())
        {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_incoming.insert(m_incoming.end(),
                              std::make_move_iterator(packets.begin()),
                              std::make_move_iterator(packets.end()));
        }
        m_notify.Notify();
    }

    std::string m_host;
    std::string m_interfaceName;
    tailgate::crypto::Bytes32 m_privateKey{};
    tailgate::crypto::Bytes32 m_publicKey{};
    bool m_preferred = false;
    tailgate::derp::DerpClient::Authenticator m_authenticator;
    std::unique_ptr<TcpStream> m_transport;
    std::unique_ptr<tailgate::net::tls::TlsStream> m_tls;
    std::unique_ptr<tailgate::derp::DerpClient> m_derp;
    EventCounter m_command;
    EventCounter m_notify;
    std::atomic_bool m_stopping = false;
    std::thread m_thread;
    std::mutex m_mutex;
    tailgate::derp::DerpSendQueue m_outgoing{MaximumQueuedPackets, MaximumQueuedBytes};
    std::vector<Packet> m_incoming;
};

DerpWorker::DerpWorker(const std::string& host,
                       const std::string& interfaceName,
                       const tailgate::crypto::Bytes32& privateKey,
                       const tailgate::crypto::Bytes32& publicKey,
                       bool preferred,
                       tailgate::derp::DerpClient::Authenticator authenticator)
    : m_impl(std::make_unique<Impl>(
          host, interfaceName, privateKey, publicKey, preferred, std::move(authenticator)))
{
}

DerpWorker::~DerpWorker() = default;

int DerpWorker::NotifyFd() const
{
    return m_impl->NotifyFd();
}

void DerpWorker::Send(const Key& destination, std::vector<std::uint8_t> packet, Priority priority)
{
    m_impl->Send(destination, std::move(packet), priority);
}

std::vector<DerpWorker::Packet> DerpWorker::ReceivePackets()
{
    return m_impl->ReceivePackets();
}

} // namespace tailgate::linux_frontend
