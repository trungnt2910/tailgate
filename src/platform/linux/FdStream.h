#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/base/ByteStream.h>

namespace tailgate::linux_frontend
{

class FdStream final : public tailgate::base::ByteStream
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
    // A read budget is an upper bound; stream callers can consume larger transfers in chunks.
    static constexpr std::size_t MaximumReadSize = 64U * 1024U;
    int m_fd = -1;
    std::optional<std::chrono::steady_clock::time_point> m_readDeadline;
    std::vector<std::uint8_t> m_readBuffer;
};

} // namespace tailgate::linux_frontend
