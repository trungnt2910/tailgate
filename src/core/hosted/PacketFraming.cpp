#include "tailgate/hosted/PacketFraming.h"

#include <algorithm>
#include <format>
#include <iterator>
#include <limits>
#include <utility>

#include <tailgate/base/Logging.h>
#include <tailgate/hosted/Protocol.h>

namespace tailgate::hosted
{

const char* PacketFramingError::what() const noexcept
{
    switch (m_code)
    {
    case PacketFramingErrorCode::InvalidCapacity:
        return "Relay transport buffer cannot hold a fragment.";
    case PacketFramingErrorCode::InvalidFragment:
        return "Relay transport fragment is invalid.";
    case PacketFramingErrorCode::OverlappingFragment:
        return "Relay transport fragments overlap.";
    case PacketFramingErrorCode::WindowExceeded:
        return "Relay transport reassembly window exceeded.";
    case PacketFramingErrorCode::NestedFragment:
        return "Relay transport fragments cannot be nested.";
    case PacketFramingErrorCode::MixedFraming:
        return "Relay transport changed framing within a stream.";
    }
    return "Unknown relay transport framing error.";
}

void PacketEncoder::Queue(std::vector<std::uint8_t> bytes)
{
    if (bytes.size() > MaximumPendingBytes - m_pendingBytes)
    {
        throw PacketFramingError(PacketFramingErrorCode::WindowExceeded);
    }
    if (!bytes.empty())
    {
        const auto size = bytes.size();
        m_pending.push_back(std::move(bytes));
        m_pendingBytes += size;
    }
}

bool PacketEncoder::HasPending() const noexcept
{
    return !m_pending.empty();
}

std::vector<std::uint8_t> PacketEncoder::Next(std::size_t capacity)
{
    constexpr std::size_t Overhead = Frame::HeaderSize + OffsetSize;
    if (capacity <= Overhead)
    {
        throw PacketFramingError(PacketFramingErrorCode::InvalidCapacity);
    }
    const auto count =
        std::min({m_pendingBytes, capacity - Overhead, Frame::MaximumPayloadSize - OffsetSize});
    if (count == 0)
    {
        return {};
    }
    if (count > std::numeric_limits<std::uint64_t>::max() - m_offset)
    {
        throw PacketFramingError(PacketFramingErrorCode::InvalidFragment);
    }
    std::vector<std::uint8_t> payload;
    payload.reserve(OffsetSize + count);
    for (std::size_t index = 0; index < OffsetSize; ++index)
    {
        constexpr unsigned BitsPerByte = 8;
        const auto shift = static_cast<unsigned>((OffsetSize - index - 1) * BitsPerByte);
        payload.push_back(static_cast<std::uint8_t>(m_offset >> shift));
    }
    std::size_t remaining = count;
    for (auto part = m_pending.begin(); remaining != 0; ++part)
    {
        const auto offset = part == m_pending.begin() ? m_pendingOffset : 0;
        const auto size = std::min(remaining, part->size() - offset);
        payload.insert(payload.end(),
                       part->begin() + static_cast<std::ptrdiff_t>(offset),
                       part->begin() + static_cast<std::ptrdiff_t>(offset + size));
        remaining -= size;
    }
    auto encoded = Frame(MessageType::Fragment, std::move(payload)).Encode();
    remaining = count;
    while (remaining != 0)
    {
        const auto size = std::min(remaining, m_pending.front().size() - m_pendingOffset);
        m_pendingOffset += size;
        remaining -= size;
        if (m_pendingOffset == m_pending.front().size())
        {
            m_pending.pop_front();
            m_pendingOffset = 0;
        }
    }
    m_offset += count;
    m_pendingBytes -= count;
    return encoded;
}

void PacketReassembler::Accept(std::span<const std::uint8_t> payload)
{
    if (payload.size() <= PacketEncoder::OffsetSize)
    {
        throw PacketFramingError(PacketFramingErrorCode::InvalidFragment);
    }
    std::uint64_t offset = 0;
    for (const auto byte : payload.first(PacketEncoder::OffsetSize))
    {
        constexpr unsigned BitsPerByte = 8;
        offset = (offset << BitsPerByte) | byte;
    }
    const auto data = payload.subspan(PacketEncoder::OffsetSize);
    if (offset < m_offset)
    {
        throw PacketFramingError(PacketFramingErrorCode::OverlappingFragment);
    }
    if (data.size() > MaximumWindow || offset - m_offset > MaximumWindow - data.size() ||
        data.size() > std::numeric_limits<std::uint64_t>::max() - offset ||
        m_fragments.size() >= MaximumFragments)
    {
        throw PacketFramingError(PacketFramingErrorCode::WindowExceeded);
    }
    const auto next = m_fragments.lower_bound(offset);
    if ((next != m_fragments.end() && offset + data.size() > next->first) ||
        (next != m_fragments.begin() &&
         std::prev(next)->first + std::prev(next)->second.size() > offset))
    {
        throw PacketFramingError(PacketFramingErrorCode::OverlappingFragment);
    }
    if (offset != m_offset && m_fragments.empty())
    {
        tailgate::base::Log(tailgate::base::LogLevel::Debug,
                            "relay-framing",
                            std::format("reordering transport fragments expected={} received={}",
                                        m_offset,
                                        offset));
    }
    m_fragments.emplace_hint(next, offset, std::vector<std::uint8_t>(data.begin(), data.end()));
    m_bytes += data.size();
}

std::vector<std::uint8_t> PacketReassembler::Take()
{
    const auto first = m_fragments.begin();
    if (first == m_fragments.end() || first->first != m_offset)
    {
        return {};
    }
    auto result = std::move(first->second);
    m_fragments.erase(first);
    m_offset += result.size();
    m_bytes -= result.size();
    return result;
}

std::size_t PacketReassembler::BufferedBytes() const noexcept
{
    return m_bytes;
}

} // namespace tailgate::hosted
