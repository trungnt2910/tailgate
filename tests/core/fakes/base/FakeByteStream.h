#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <tailgate/base/ByteStream.h>

namespace tailgate::tests::fakes
{

class FakeByteStream final : public tailgate::base::ByteStream
{
public:
    explicit FakeByteStream(std::string name) : Name(std::move(name))
    {
    }

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t*,
                                                          std::size_t size) override
    {
        ++WriteCalls;
        if (WriteWouldBlock)
        {
            return std::nullopt;
        }
        return size;
    }

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t) override
    {
        ++ReadCalls;
        if (ReadWouldBlock)
        {
            return std::nullopt;
        }
        return std::vector<std::uint8_t>{};
    }

    std::string Name;
    std::size_t ReadCalls{};
    std::size_t WriteCalls{};
    bool ReadWouldBlock{};
    bool WriteWouldBlock{};
};

} // namespace tailgate::tests::fakes
