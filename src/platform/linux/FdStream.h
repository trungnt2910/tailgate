#pragma once

#include "tailgate/ByteStream.h"

#include <chrono>
#include <optional>

namespace tailgate::linux_frontend
{

class FdStream final : public IByteStream
{
public:
    explicit FdStream(int fd);

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override;

    void SetReadTimeout(std::chrono::milliseconds timeout);
    void ClearReadTimeout();

private:
    int m_fd = -1;
    std::optional<std::chrono::steady_clock::time_point> m_readDeadline;
};

} // namespace tailgate::linux_frontend
