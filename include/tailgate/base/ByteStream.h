#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

namespace tailgate::base
{

class StreamWouldBlock : public std::runtime_error
{
public:
    StreamWouldBlock() : std::runtime_error("Stream would block.")
    {
    }
};

class IByteStream
{
public:
    virtual ~IByteStream() = default;

    [[nodiscard]] virtual std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                                  std::size_t size) = 0;

    virtual void WriteAll(const std::vector<std::uint8_t>& data)
    {
        std::size_t offset = 0;
        while (offset < data.size())
        {
            const std::optional<std::size_t> written =
                TryWriteSome(data.data() + offset, data.size() - offset);
            if (!written)
            {
                throw StreamWouldBlock();
            }
            if (*written == 0)
            {
                throw std::runtime_error("Stream closed during write.");
            }
            offset += *written;
        }
    }

    [[nodiscard]] virtual std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) = 0;

    [[nodiscard]] virtual std::vector<std::uint8_t> ReadSome(std::size_t maxBytes)
    {
        std::optional<std::vector<std::uint8_t>> result = TryReadSome(maxBytes);
        if (!result)
        {
            throw StreamWouldBlock();
        }
        return std::move(*result);
    }

    [[nodiscard]] virtual std::vector<std::uint8_t> ReadExact(std::size_t byteCount)
    {
        std::vector<std::uint8_t> result;
        result.reserve(byteCount);
        while (result.size() < byteCount)
        {
            std::vector<std::uint8_t> part = ReadSome(byteCount - result.size());
            if (part.empty())
            {
                throw std::runtime_error("Stream closed before enough bytes were read.");
            }
            result.insert(result.end(), part.begin(), part.end());
        }
        return result;
    }

    [[nodiscard]] virtual bool HasBufferedInput() const
    {
        return false;
    }

    [[nodiscard]] virtual bool ReadNeedsWrite() const
    {
        return false;
    }

    [[nodiscard]] virtual bool WriteNeedsRead() const
    {
        return false;
    }
};

} // namespace tailgate::base
