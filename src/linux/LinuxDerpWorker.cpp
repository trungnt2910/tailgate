#include "LinuxDerpWorker.h"

#include "LinuxFiles.h"
#include "TcpStream.h"
#include "UniqueFd.h"
#include "tailgate/Logging.h"
#include "tailgate/protocol/TlsStream.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{
namespace
{

enum class DerpEventKind : std::uint32_t
{
    Transport,
    Command,
};

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
         const protocol::Bytes32& privateKey,
         const protocol::Bytes32& publicKey,
         bool preferred)
        : m_transport(host, "443", interfaceName),
          m_tls(m_transport, host, ReadBinaryFile("/etc/ssl/certs/ca-certificates.crt")),
          m_derp(m_tls, privateKey, publicKey)
    {
        m_derp.Connect(host);
        m_derp.SetPreferred(preferred);
        m_transport.SetNonBlocking(true);
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

    void Send(const Key& destination, std::vector<std::uint8_t> packet)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_outgoing.push({destination, std::move(packet)});
        }
        m_command.Notify();
    }

    std::vector<Packet> ReceivePackets()
    {
        m_notify.Drain();
        std::vector<Packet> result;
        std::string error;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            result.swap(m_incoming);
            error = m_error;
        }
        if (!error.empty())
        {
            throw std::runtime_error(error);
        }
        return result;
    }

private:
    struct Outgoing
    {
        Key Destination{};
        std::vector<std::uint8_t> Packet;
    };

    void Run()
    {
        try
        {
            UniqueFd epollFd(epoll_create1(EPOLL_CLOEXEC));
            if (epollFd.Fd < 0)
            {
                throw std::runtime_error("DERP epoll_create1 failed: " +
                                         std::string(std::strerror(errno)));
            }
            std::uint32_t transportEvents = EPOLLIN;
            AddEpollInterest(
                epollFd.Fd, m_transport.NativeHandle(), transportEvents, DerpEventKind::Transport);
            AddEpollInterest(epollFd.Fd, m_command.Fd(), EPOLLIN, DerpEventKind::Command);

            while (!m_stopping)
            {
                FlushOutgoing();
                const std::uint32_t desiredTransportEvents =
                    m_derp.HasPendingOutput() ? static_cast<std::uint32_t>(EPOLLIN | EPOLLOUT)
                                              : static_cast<std::uint32_t>(EPOLLIN);
                if (desiredTransportEvents != transportEvents)
                {
                    ModifyEpollInterest(epollFd.Fd,
                                        m_transport.NativeHandle(),
                                        desiredTransportEvents,
                                        DerpEventKind::Transport);
                    transportEvents = desiredTransportEvents;
                }
                if (m_derp.HasBufferedInput())
                {
                    DrainIncoming();
                    continue;
                }

                epoll_event events[2]{};
                const int selected = epoll_wait(epollFd.Fd, events, 2, -1);
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
                            m_derp.Flush();
                        }
                        if ((events[index].events & EPOLLIN) != 0 || m_derp.HasBufferedInput())
                        {
                            DrainIncoming();
                        }
                    }
                }
            }
        }
        catch (const std::exception& error)
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_error = error.what();
            }
            try
            {
                m_notify.Notify();
            }
            catch (...)
            {
            }
        }
    }

    void FlushOutgoing()
    {
        std::queue<Outgoing> outgoing;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            outgoing.swap(m_outgoing);
        }
        while (!outgoing.empty())
        {
            m_derp.Send(outgoing.front().Destination, outgoing.front().Packet);
            outgoing.pop();
        }
    }

    void DrainIncoming()
    {
        std::vector<Packet> packets = m_derp.ReceiveAvailableBatch();
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

    TcpStream m_transport;
    protocol::TlsStream m_tls;
    protocol::DerpClient m_derp;
    EventCounter m_command;
    EventCounter m_notify;
    std::atomic_bool m_stopping = false;
    std::thread m_thread;
    std::mutex m_mutex;
    std::queue<Outgoing> m_outgoing;
    std::vector<Packet> m_incoming;
    std::string m_error;
};

DerpWorker::DerpWorker(const std::string& host,
                       const std::string& interfaceName,
                       const protocol::Bytes32& privateKey,
                       const protocol::Bytes32& publicKey,
                       bool preferred)
    : m_impl(std::make_unique<Impl>(host, interfaceName, privateKey, publicKey, preferred))
{
}

DerpWorker::~DerpWorker() = default;

int DerpWorker::NotifyFd() const
{
    return m_impl->NotifyFd();
}

void DerpWorker::Send(const Key& destination, std::vector<std::uint8_t> packet)
{
    m_impl->Send(destination, std::move(packet));
}

std::vector<DerpWorker::Packet> DerpWorker::ReceivePackets()
{
    return m_impl->ReceivePackets();
}

} // namespace tailgate::linux_frontend
