#include <tailgate/serve/PeerApiConnection.h>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace tailgate::serve
{
namespace
{

constexpr std::size_t CopyBufferSize = 16U * 1024U;
constexpr std::size_t MaximumQueuedBytes = 4U * 1024U * 1024U;
constexpr std::size_t MaximumReadsPerCycle = 16;

class PendingWrites final
{
public:
    void Push(std::vector<std::uint8_t> data)
    {
        m_bytes += data.size();
        if (m_bytes > MaximumQueuedBytes)
        {
            throw std::runtime_error("Peer API forwarding queue limit exceeded.");
        }
        m_buffers.push_back(std::move(data));
    }

    bool Flush(tailgate::base::ByteStream& stream)
    {
        while (!m_buffers.empty())
        {
            const std::vector<std::uint8_t>& data = m_buffers.front();
            const std::optional<std::size_t> written =
                stream.TryWriteSome(data.data() + m_offset, data.size() - m_offset);
            if (!written)
            {
                return false;
            }
            if (*written == 0)
            {
                throw std::runtime_error("Peer API forwarding stream closed during write.");
            }
            m_offset += *written;
            if (m_offset == data.size())
            {
                m_bytes -= data.size();
                m_buffers.pop_front();
                m_offset = 0;
            }
        }
        return true;
    }

    [[nodiscard]] bool Empty() const noexcept
    {
        return m_buffers.empty();
    }

private:
    std::deque<std::vector<std::uint8_t>> m_buffers;
    std::size_t m_offset{};
    std::size_t m_bytes{};
};

PeerApiConnectionStatus Drain(tailgate::base::ByteStream& input, PendingWrites& output)
{
    for (std::size_t read = 0; read < MaximumReadsPerCycle; ++read)
    {
        std::optional<std::vector<std::uint8_t>> data = input.TryReadSome(CopyBufferSize);
        if (!data)
        {
            return PeerApiConnectionStatus::Ready;
        }
        if (data->empty())
        {
            return PeerApiConnectionStatus::Closed;
        }
        output.Push(std::move(*data));
    }
    return PeerApiConnectionStatus::Ready;
}

} // namespace

class PeerApiConnection::Impl
{
public:
    Impl(tailgate::base::ByteStream& peer, tailgate::base::ByteStream& local)
        : Peer(peer), Local(local)
    {
    }

    tailgate::base::ByteStream& Peer;
    tailgate::base::ByteStream& Local;
    PendingWrites ToPeer;
    PendingWrites ToLocal;
};

PeerApiConnection::PeerApiConnection(tailgate::base::ByteStream& peer,
                                     tailgate::base::ByteStream& local)
    : m_impl(std::make_unique<Impl>(peer, local))
{
}

PeerApiConnection::~PeerApiConnection() = default;

PeerApiConnectionStatus PeerApiConnection::ProcessPeerInput()
{
    return Drain(m_impl->Peer, m_impl->ToLocal);
}

PeerApiConnectionStatus PeerApiConnection::ProcessLocalInput()
{
    return Drain(m_impl->Local, m_impl->ToPeer);
}

bool PeerApiConnection::FlushPeerOutput()
{
    return m_impl->ToPeer.Flush(m_impl->Peer);
}

bool PeerApiConnection::FlushLocalOutput()
{
    return m_impl->ToLocal.Flush(m_impl->Local);
}

bool PeerApiConnection::PeerOutputPending() const noexcept
{
    return !m_impl->ToPeer.Empty();
}

bool PeerApiConnection::LocalOutputPending() const noexcept
{
    return !m_impl->ToLocal.Empty();
}

} // namespace tailgate::serve
