#include "UwpStreamIo.h"

#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <utility>

#include "WinrtOperation.h"

namespace tailgate::uwp
{
namespace
{
namespace foundation = winrt::Windows::Foundation;
namespace streams = winrt::Windows::Storage::Streams;

std::vector<std::uint8_t> BytesFromBuffer(const streams::IBuffer& buffer,
                                          const tailgate::base::Logger& logger)
{
    const std::uint32_t length = buffer.Length();
    logger.LogTrace("tcp read {}", length);
    std::vector<std::uint8_t> result(length);
    if (length != 0)
    {
        streams::DataReader reader = streams::DataReader::FromBuffer(buffer);
        reader.ReadBytes(winrt::array_view<std::uint8_t>(result));
    }
    return result;
}

} // namespace

struct UwpStreamIo::Notifications
{
    std::mutex Mutex;
    std::optional<std::reference_wrapper<tailgate::base::EventLoop>> Events;
    tailgate::base::EventToken Token;

    void Post(tailgate::base::EventReadiness readiness)
    {
        std::lock_guard lock(Mutex);
        if (Events)
        {
            Events->get().Post(tailgate::base::Event{.Token = Token, .Readiness = readiness});
        }
    }
};

UwpStreamIo::~UwpStreamIo()
{
    Close();
}

UwpStreamIo::UwpStreamIo(streams::IInputStream input,
                         streams::IOutputStream output,
                         StreamIoOptions options)
    : m_notifications(std::make_shared<Notifications>()),
      m_input(std::move(input)),
      m_output(std::move(output)),
      m_ioTimeout(options.Timeout),
      m_readTimeout(options.Timeout),
      m_cancellation(options.Cancellation)
{
    m_notifications->Events = options.Events;
    m_notifications->Token = options.Token;
}

namespace
{

// Normalize the platform boundary so shared transport recovery sees the same error
// contract for immediate WinRT failures and asynchronous completion failures.
template <typename Operation>
auto StartIo(Operation&& operation)
{
    try
    {
        return operation();
    }
    catch (const winrt::hresult_error& error)
    {
        throw std::system_error(error.code().value, std::system_category());
    }
}

void CheckIoCompletion(const foundation::IAsyncInfo& operation)
{
    if (operation.Status() == foundation::AsyncStatus::Error)
    {
        throw std::system_error(operation.ErrorCode().value, std::system_category());
    }
    if (operation.Status() == foundation::AsyncStatus::Canceled)
    {
        throw std::system_error(std::make_error_code(std::errc::operation_canceled));
    }
}

} // namespace

std::optional<std::size_t> UwpStreamIo::TryWriteSome(const std::uint8_t* data, std::size_t size)
{
    if (m_pendingWrite)
    {
        if (m_pendingWrite.Status() == foundation::AsyncStatus::Started)
        {
            return std::nullopt;
        }
        auto completed = std::exchange(m_pendingWrite, nullptr);
        CheckIoCompletion(completed);
        return static_cast<std::size_t>(completed.GetResults());
    }
    streams::Buffer buffer(static_cast<std::uint32_t>(size));
    std::copy(data, data + size, buffer.data());
    buffer.Length(static_cast<std::uint32_t>(size));
    auto operation = StartIo(
        [&]
        {
            return m_output.WriteAsync(buffer);
        });
    if (m_nonBlockingReads)
    {
        m_pendingWrite = std::move(operation);
        if (m_notifications)
        {
            m_pendingWrite.Completed(
                [notify = m_notifications](const auto&, auto)
                {
                    notify->Post(tailgate::base::EventReadiness::Writable);
                });
        }
        return std::nullopt;
    }
    return static_cast<std::size_t>(AwaitOperation(operation, m_ioTimeout, m_cancellation));
}

std::optional<std::vector<std::uint8_t>> UwpStreamIo::TryReadSome(std::size_t maxBytes)
{
    if (!m_nonBlockingReads)
    {
        streams::Buffer buffer(static_cast<std::uint32_t>(maxBytes));
        auto read = StartIo(
            [&]
            {
                return m_input.ReadAsync(buffer,
                                         static_cast<std::uint32_t>(maxBytes),
                                         streams::InputStreamOptions::Partial);
            });
        return BytesFromBuffer(AwaitOperation(read, m_readTimeout, m_cancellation), m_logger);
    }

    if (maxBytes == 0)
    {
        return std::vector<std::uint8_t>{};
    }
    if (m_readBuffer.empty())
    {
        if (!m_pendingRead)
        {
            BeginRead(maxBytes);
        }
        if (m_pendingRead.Status() == foundation::AsyncStatus::Started)
        {
            return std::nullopt;
        }
        auto completed = std::exchange(m_pendingRead, nullptr);
        CheckIoCompletion(completed);
        m_readBuffer = BytesFromBuffer(completed.GetResults(), m_logger);
        m_readOffset = 0;
        if (m_readBuffer.empty())
        {
            return std::vector<std::uint8_t>{};
        }
    }
    const auto count = std::min(maxBytes, m_readBuffer.size() - m_readOffset);
    std::vector<std::uint8_t> bytes(m_readBuffer.begin() + m_readOffset,
                                    m_readBuffer.begin() + m_readOffset + count);
    m_readOffset += count;
    if (m_readOffset == m_readBuffer.size())
    {
        m_readBuffer.clear();
        m_readOffset = 0;
    }
    if (!m_pendingRead)
    {
        BeginRead(maxBytes);
    }
    return bytes;
}

bool UwpStreamIo::HasBufferedInput() const
{
    return !m_readBuffer.empty() ||
           (m_pendingRead && m_pendingRead.Status() != foundation::AsyncStatus::Started);
}

void UwpStreamIo::BeginRead(std::size_t maximumSize)
{
    constexpr std::size_t MaximumReadChunk = 64U * 1024U;
    const auto count = static_cast<std::uint32_t>(std::min(maximumSize, MaximumReadChunk));
    streams::Buffer buffer(count);
    m_pendingRead = StartIo(
        [&]
        {
            return m_input.ReadAsync(buffer, count, streams::InputStreamOptions::Partial);
        });
    if (m_notifications)
    {
        m_pendingRead.Completed(
            [notify = m_notifications](const auto&, auto)
            {
                notify->Post(tailgate::base::EventReadiness::Readable);
            });
    }
}

void UwpStreamIo::SetReadTimeout(std::optional<std::chrono::seconds> timeout)
{
    m_readTimeout = timeout;
}

void UwpStreamIo::SetNonBlockingReads(bool enabled)
{
    if (!enabled && m_pendingRead)
    {
        m_pendingRead.Cancel();
        m_pendingRead = nullptr;
    }
    m_nonBlockingReads = enabled;
    if (enabled && m_notifications && !m_pendingRead)
    {
        // Arm the first read so completion can wake an otherwise idle event loop.
        BeginRead(1);
    }
}

void UwpStreamIo::SetWriteInterest(bool enabled)
{
    if (enabled && m_notifications && !m_pendingWrite)
    {
        m_notifications->Post(tailgate::base::EventReadiness::Writable);
    }
}

void UwpStreamIo::SetNonBlocking(bool enabled)
{
    if (!enabled && (m_pendingWrite || m_pendingRead || !m_readBuffer.empty()))
    {
        throw std::logic_error("Cannot change TCP mode with pending I/O.");
    }
    SetNonBlockingReads(enabled);
}

void UwpStreamIo::Close() noexcept
{
    if (m_notifications)
    {
        std::lock_guard lock(m_notifications->Mutex);
        m_notifications->Events.reset();
    }
    try
    {
        if (m_pendingRead)
        {
            m_pendingRead.Cancel();
        }
        if (m_pendingWrite)
        {
            m_pendingWrite.Cancel();
        }
    }
    catch (...)
    {
        // Completed or closed operations no longer need cancellation.
    }
}

} // namespace tailgate::uwp
