#pragma once

#include <mutex>
#include <span>

#include <tailgate/base/ByteStream.h>

namespace tailgate::uwp::bg
{

// Authentication reads the socket directly. After channel startup Windows owns
// receives; Decapsulate supplies bytes and only the transport worker consumes them.
class VpnCallbackStream final : public base::ByteStream
{
public:
    static constexpr std::size_t MaximumBufferedBytes = 4U * 1024U * 1024U;
    explicit VpnCallbackStream(base::ByteStream& socket);
    void UseCallbackInput();
    [[nodiscard]] bool AppendInput(std::span<const std::uint8_t> bytes);
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maximum) override;
    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] bool HasBufferedInput() const override;

private:
    base::ByteStream& m_socket;
    mutable std::mutex m_mutex;
    std::vector<std::uint8_t> m_input;
    bool m_callbackInput = false;
};

} // namespace tailgate::uwp::bg
