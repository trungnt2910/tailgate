#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/base/ByteStream.h>

namespace tailgate::tests::support
{

class BufferedByteStream final : public tailgate::base::ByteStream
{
public:
    BufferedByteStream(bool buffered, bool readNeedsWrite = false)
        : m_buffered(buffered), m_readNeedsWrite(readNeedsWrite)
    {
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t*, std::size_t size) override
    {
        return size;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t) override
    {
        return std::nullopt;
    }

    bool HasBufferedInput() const override
    {
        return m_buffered;
    }

    bool ReadNeedsWrite() const override
    {
        return m_readNeedsWrite;
    }

private:
    bool m_buffered;
    bool m_readNeedsWrite;
};

} // namespace tailgate::tests::support
