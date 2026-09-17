#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <map>
#include <span>
#include <vector>

namespace tailgate::hosted
{

enum class PacketFramingErrorCode
{
    InvalidCapacity,
    InvalidFragment,
    OverlappingFragment,
    WindowExceeded,
    NestedFragment,
    MixedFraming,
};

class PacketFramingError final : public std::exception
{
public:
    explicit PacketFramingError(PacketFramingErrorCode code) noexcept : m_code(code)
    {
    }

    [[nodiscard]] PacketFramingErrorCode Code() const noexcept
    {
        return m_code;
    }

    [[nodiscard]] const char* what() const noexcept override;

private:
    PacketFramingErrorCode m_code;
};

// Each transport buffer is a complete frame. Offsets preserve stream order when the
// transport schedules buffers from different callbacks independently.
class PacketEncoder final
{
public:
    static constexpr std::size_t OffsetSize = sizeof(std::uint64_t);
    static constexpr std::size_t MaximumPendingBytes = 4U * 1024U * 1024U;
    void Queue(std::vector<std::uint8_t> bytes);
    [[nodiscard]] std::vector<std::uint8_t> Next(std::size_t capacity);
    [[nodiscard]] bool HasPending() const noexcept;

private:
    std::uint64_t m_offset = 0;
    std::deque<std::vector<std::uint8_t>> m_pending;
    std::size_t m_pendingOffset = 0;
    std::size_t m_pendingBytes = 0;
};

class PacketReassembler final
{
public:
    static constexpr std::size_t MaximumWindow = 4U * 1024U * 1024U;
    static constexpr std::size_t MaximumFragments = 4096;
    void Accept(std::span<const std::uint8_t> payload);
    [[nodiscard]] std::vector<std::uint8_t> Take();
    [[nodiscard]] std::size_t BufferedBytes() const noexcept;

private:
    std::map<std::uint64_t, std::vector<std::uint8_t>> m_fragments;
    std::uint64_t m_offset = 0;
    std::size_t m_bytes = 0;
};

} // namespace tailgate::hosted
