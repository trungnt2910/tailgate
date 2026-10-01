#include "tailgate/hosted/StreamTransport.h"

#include <system_error>
#include <utility>

namespace tailgate::hosted
{

StreamTransport::StreamTransport(std::unique_ptr<types::nettype::TcpSocket> socket, Decoder decoder)
    : m_socket(std::move(socket)), m_decoder(std::move(decoder))
{
    m_socket->SetNonBlocking(true);
}

StreamTransport::~StreamTransport()
{
    Close();
}

bool StreamTransport::Queue(std::vector<std::uint8_t> bytes)
{
    if (bytes.size() > MaximumQueuedBytes - m_queuedBytes)
    {
        return false;
    }
    if (!bytes.empty())
    {
        m_queuedBytes += bytes.size();
        m_output.push_back(std::move(bytes));
    }
    return true;
}

bool StreamTransport::Flush(std::size_t maximumWrites)
{
    if (m_socket->ReadNeedsWrite())
    {
        UpdateWriteInterest();
        return false;
    }
    for (std::size_t count = 0; count < maximumWrites && !m_output.empty(); ++count)
    {
        const auto& bytes = m_output.front();
        const auto remaining = bytes.size() - m_offset;
        const auto written = m_socket->TryWriteSome(bytes.data() + m_offset, remaining);
        if (!written)
        {
            UpdateWriteInterest();
            return false;
        }
        if (*written == 0 || *written > remaining)
        {
            throw std::system_error(std::make_error_code(std::errc::connection_reset));
        }
        m_offset += *written;
        m_queuedBytes -= *written;
        if (m_offset == bytes.size())
        {
            m_output.pop_front();
            m_offset = 0;
        }
    }
    UpdateWriteInterest();
    return !m_output.empty();
}

std::vector<Frame> StreamTransport::Receive(std::size_t maximumReads, std::size_t maximumFrames)
{
    if (m_closed)
    {
        throw std::system_error(std::make_error_code(std::errc::connection_reset));
    }
    std::vector<Frame> frames;
    std::size_t reads = 0;
    m_moreFrames = false;
    m_moreReads = false;
    while (frames.size() < maximumFrames)
    {
        if (auto frame = m_decoder.Next())
        {
            frames.push_back(std::move(*frame));
            continue;
        }
        if (reads >= maximumReads || m_socket->WriteNeedsRead())
        {
            break;
        }
        auto bytes = m_socket->TryReadSome(MaximumReadSize);
        ++reads;
        if (!bytes)
        {
            break;
        }
        if (bytes->empty())
        {
            m_closed = true;
            if (frames.empty())
            {
                throw std::system_error(std::make_error_code(std::errc::connection_reset));
            }
            break;
        }
        m_decoder.Feed(*bytes);
        m_moreReads = reads == maximumReads;
    }
    // A full frame batch may leave decoded frames behind. Re-enter once without
    // waiting for a new socket event; the following incomplete batch clears this.
    m_moreFrames = maximumFrames != 0 && frames.size() == maximumFrames;
    UpdateWriteInterest();
    return frames;
}

bool StreamTransport::HasBufferedInput() const
{
    return m_closed || m_moreFrames ||
           (!m_socket->WriteNeedsRead() && (m_moreReads || m_socket->HasBufferedInput()));
}

void StreamTransport::UpdateWriteInterest()
{
    m_socket->SetWriteInterest(m_socket->ReadNeedsWrite() ||
                               (!m_output.empty() && !m_socket->WriteNeedsRead()));
}

void StreamTransport::Close() noexcept
{
    m_socket->Close();
}

} // namespace tailgate::hosted
