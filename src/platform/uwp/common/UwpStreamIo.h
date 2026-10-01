#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>

#include <winrt/Windows.Storage.Streams.h>

#include <tailgate/base/ByteStream.h>
#include <tailgate/base/EventLoop.h>
#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

namespace tailgate::uwp
{

struct StreamIoOptions
{
    std::chrono::seconds Timeout{20};
    std::stop_token Cancellation{};
    std::optional<std::reference_wrapper<tailgate::base::EventLoop>> Events{};
    tailgate::base::EventToken Token{};
};

class UwpStreamIo final : public tailgate::base::ByteStream
{
public:
    UwpStreamIo(winrt::Windows::Storage::Streams::IInputStream input,
                winrt::Windows::Storage::Streams::IOutputStream output,
                StreamIoOptions options);
    ~UwpStreamIo() override;

    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maxBytes) override;
    [[nodiscard]] bool HasBufferedInput() const override;
    void SetReadTimeout(std::optional<std::chrono::seconds> timeout);
    void SetWriteInterest(bool enabled);
    void SetNonBlocking(bool enabled);
    void Close() noexcept;

private:
    void SetNonBlockingReads(bool enabled);
    void BeginRead(std::size_t maximumSize);
    struct Notifications;
    std::shared_ptr<Notifications> m_notifications;

    winrt::Windows::Storage::Streams::IInputStream m_input{nullptr};
    winrt::Windows::Storage::Streams::IOutputStream m_output{nullptr};
    std::chrono::seconds m_ioTimeout;
    std::optional<std::chrono::seconds> m_readTimeout;
    winrt::Windows::Foundation::
        IAsyncOperationWithProgress<winrt::Windows::Storage::Streams::IBuffer, std::uint32_t>
            m_pendingRead{nullptr};
    winrt::Windows::Foundation::IAsyncOperationWithProgress<std::uint32_t, std::uint32_t>
        m_pendingWrite{nullptr};
    std::stop_token m_cancellation;
    std::vector<std::uint8_t> m_readBuffer;
    std::size_t m_readOffset = 0;
    bool m_nonBlockingReads = false;
    tailgate::base::Logger m_logger{"uwp-tcp"};
};

} // namespace tailgate::uwp
