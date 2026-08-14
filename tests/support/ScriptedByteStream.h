#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>
#include <vector>

#include <tailgate/ByteStream.h>

namespace tailgate::test
{

class ScriptedByteStream final : public IByteStream
{
public:
    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override
    {
        ++WriteCalls;
        if (BlockedWrites > 0)
        {
            --BlockedWrites;
            return std::nullopt;
        }
        const std::size_t written = std::min(size, MaximumWriteSize);
        Written.insert(Written.end(), data, data + written);
        return written;
    }

    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override
    {
        ++ReadCalls;
        if (Reads.empty())
        {
            return std::nullopt;
        }
        if (!Reads.front())
        {
            Reads.pop_front();
            return std::nullopt;
        }
        std::vector<std::uint8_t>& queued = *Reads.front();
        const std::size_t size = std::min(maxBytes, queued.size());
        std::vector<std::uint8_t> result(queued.begin(),
                                         queued.begin() + static_cast<std::ptrdiff_t>(size));
        queued.erase(queued.begin(), queued.begin() + static_cast<std::ptrdiff_t>(size));
        if (queued.empty())
        {
            Reads.pop_front();
        }
        return result;
    }

    [[nodiscard]] bool HasBufferedInput() const override
    {
        return !Reads.empty() && Reads.front().has_value();
    }

    void QueueRead(std::vector<std::uint8_t> bytes)
    {
        Reads.push_back(std::move(bytes));
    }

    void QueueWouldBlock()
    {
        Reads.push_back(std::nullopt);
    }

    std::size_t MaximumWriteSize = std::numeric_limits<std::size_t>::max();
    std::size_t BlockedWrites = 0;
    std::size_t ReadCalls = 0;
    std::size_t WriteCalls = 0;
    std::vector<std::uint8_t> Written;
    std::deque<std::optional<std::vector<std::uint8_t>>> Reads;
};

} // namespace tailgate::test
