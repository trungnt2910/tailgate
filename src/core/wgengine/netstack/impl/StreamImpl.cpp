#include "StreamImpl.h"

#include <algorithm>
#include <limits>
#include <mutex>
#include <new>
#include <utility>

#include <tailgate/wgengine/netstack/Error.h>

namespace tailgate::wgengine::netstack::impl
{

StreamImpl::StreamImpl(std::shared_ptr<Runtime> runtime, tcp_pcb* pcb, StreamState state)
    : m_runtime(std::move(runtime)), m_pcb(pcb), m_state(state)
{
    if (!m_runtime->Track(pcb, Destroyed, this))
    {
        throw Exception(Error::CapacityExceeded);
    }
    InstallCallbacks();
}

StreamImpl::~StreamImpl()
{
    Abort();
}

std::optional<std::size_t> StreamImpl::TryWriteSome(const std::uint8_t* data, std::size_t size)
{
    std::lock_guard lock(m_runtime->Mutex());
    if (m_state == StreamState::Failed)
    {
        throw Exception(Error::ConnectionFailed);
    }
    if (m_writeEof || m_pcb == nullptr)
    {
        return 0;
    }
    if (m_state == StreamState::Connecting)
    {
        return std::nullopt;
    }
    const auto count = static_cast<std::uint16_t>(
        std::min({size,
                  static_cast<std::size_t>(tcp_sndbuf(m_pcb)),
                  static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max())}));
    if (count == 0 && size != 0)
    {
        return std::nullopt;
    }
    const auto error = tcp_write(m_pcb, data, count, TCP_WRITE_FLAG_COPY);
    if (error == ERR_MEM)
    {
        return std::nullopt;
    }
    if (error != ERR_OK)
    {
        throw Exception(Error::ConnectionFailed);
    }
    // Once tcp_write accepts bytes, output pressure must not make the caller resend
    // them. lwIP owns them and its ACK/retransmission machinery handles retry.
    (void)tcp_output(m_pcb);
    return count;
}

std::optional<std::vector<std::uint8_t>> StreamImpl::TryReadSome(std::size_t maximumBytes)
{
    std::lock_guard lock(m_runtime->Mutex());
    if (maximumBytes == 0)
    {
        return std::vector<std::uint8_t>{};
    }
    if (m_received.empty())
    {
        if (m_state == StreamState::Failed)
        {
            throw Exception(Error::ConnectionFailed);
        }
        if (m_readEof || m_pcb == nullptr)
        {
            return std::vector<std::uint8_t>{};
        }
        return std::nullopt;
    }
    const auto& front = m_received.front();
    const auto count =
        std::min({maximumBytes,
                  front.size() - m_receiveOffset,
                  static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max())});
    std::vector<std::uint8_t> result(front.begin() + static_cast<std::ptrdiff_t>(m_receiveOffset),
                                     front.begin() +
                                         static_cast<std::ptrdiff_t>(m_receiveOffset + count));
    m_receiveOffset += count;
    m_receiveBytes -= count;
    if (m_receiveOffset == front.size())
    {
        m_received.pop_front();
        m_receiveOffset = 0;
    }
    if (m_pcb != nullptr)
    {
        tcp_recved(m_pcb, static_cast<std::uint16_t>(count));
        (void)tcp_output(m_pcb);
    }
    return result;
}

bool StreamImpl::HasBufferedInput() const
{
    std::lock_guard lock(m_runtime->Mutex());
    return !m_received.empty();
}

StreamState StreamImpl::State() const
{
    std::lock_guard lock(m_runtime->Mutex());
    return m_state;
}

namespace
{

constexpr std::size_t MaximumReceiveBytes = TCP_WND;

} // namespace

void StreamImpl::InstallCallbacks() noexcept
{
    tcp_arg(m_pcb, this);
    tcp_recv(m_pcb, Received);
    tcp_err(m_pcb, Failed);
}

bool StreamImpl::TryShutdownWrite()
{
    std::lock_guard lock(m_runtime->Mutex());
    if (m_pcb == nullptr || m_writeEof)
    {
        return true;
    }
    if (m_state == StreamState::Connecting)
    {
        return false;
    }
    const auto error = tcp_shutdown(m_pcb, 0, 1);
    if (error == ERR_MEM)
    {
        return false;
    }
    if (error != ERR_OK)
    {
        throw Exception(Error::ConnectionFailed);
    }
    m_writeEof = true;
    return true;
}

bool StreamImpl::TryClose()
{
    std::lock_guard lock(m_runtime->Mutex());
    if (m_pcb == nullptr)
    {
        return true;
    }
    auto* pcb = m_pcb;
    tcp_arg(pcb, nullptr);
    tcp_recv(pcb, nullptr);
    tcp_err(pcb, nullptr);
    const auto error = tcp_close(pcb);
    if (error != ERR_OK)
    {
        InstallCallbacks();
        return false;
    }
    // Successful close may retain a PCB in FIN_WAIT/TIME_WAIT; runtime keeps its
    // lifetime tracking, but it must no longer reference this application stream.
    if (m_pcb != nullptr)
    {
        (void)m_runtime->Track(m_pcb);
    }
    m_pcb = nullptr;
    m_state = StreamState::Closed;
    return true;
}

void StreamImpl::Abort() noexcept
{
    std::lock_guard lock(m_runtime->Mutex());
    if (m_pcb != nullptr)
    {
        tcp_abort(m_pcb);
    }
}

void StreamImpl::Destroyed(void* context) noexcept
{
    auto& stream = *static_cast<StreamImpl*>(context);
    stream.m_pcb = nullptr;
    stream.m_state = StreamState::Closed;
}

void StreamImpl::Failed(void* context, err_t) noexcept
{
    auto& stream = *static_cast<StreamImpl*>(context);
    stream.m_pcb = nullptr;
    stream.m_state = StreamState::Failed;
}

err_t StreamImpl::Connected(void* context, tcp_pcb*, err_t error) noexcept
{
    auto& stream = *static_cast<StreamImpl*>(context);
    stream.m_state = error == ERR_OK ? StreamState::Open : StreamState::Failed;
    return ERR_OK;
}

err_t StreamImpl::Received(void* context, tcp_pcb*, pbuf* buffer, err_t error) noexcept
{
    auto& stream = *static_cast<StreamImpl*>(context);
    if (buffer == nullptr)
    {
        stream.m_readEof = true;
        return ERR_OK;
    }
    if (error != ERR_OK)
    {
        return error;
    }
    if (buffer->tot_len > MaximumReceiveBytes - stream.m_receiveBytes)
    {
        return ERR_MEM;
    }
    try
    {
        std::vector<std::uint8_t> bytes(buffer->tot_len);
        (void)pbuf_copy_partial(buffer, bytes.data(), buffer->tot_len, 0);
        stream.m_received.push_back(std::move(bytes));
        stream.m_receiveBytes += buffer->tot_len;
        pbuf_free(buffer);
        return ERR_OK;
    }
    catch (const std::bad_alloc&)
    {
        // Ownership stays with lwIP, which retries refused data from its timer.
        return ERR_MEM;
    }
}

} // namespace tailgate::wgengine::netstack::impl
