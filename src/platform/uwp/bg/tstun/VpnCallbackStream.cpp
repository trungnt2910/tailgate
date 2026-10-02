#include "VpnCallbackStream.h"

#include <algorithm>

namespace tailgate::uwp::bg
{

VpnCallbackStream::VpnCallbackStream(base::ByteStream& socket) : m_socket(socket)
{
}

void VpnCallbackStream::UseCallbackInput()
{
    std::lock_guard lock(m_mutex);
    m_callbackInput = true;
}

bool VpnCallbackStream::AppendInput(std::span<const std::uint8_t> bytes)
{
    std::lock_guard lock(m_mutex);
    if (!m_callbackInput || bytes.size() > MaximumBufferedBytes - m_input.size())
    {
        return false;
    }
    m_input.insert(m_input.end(), bytes.begin(), bytes.end());
    return true;
}

std::optional<std::vector<std::uint8_t>> VpnCallbackStream::TryReadSome(std::size_t maximum)
{
    std::unique_lock lock(m_mutex);
    if (!m_callbackInput)
    {
        lock.unlock();
        return m_socket.TryReadSome(maximum);
    }
    if (m_input.empty())
    {
        return std::nullopt;
    }
    const auto count = std::min(maximum, m_input.size());
    const auto end = m_input.begin() + static_cast<std::ptrdiff_t>(count);
    std::vector<std::uint8_t> result(m_input.begin(), end);
    m_input.erase(m_input.begin(), end);
    return result;
}

std::optional<std::size_t> VpnCallbackStream::TryWriteSome(const std::uint8_t* data,
                                                           std::size_t size)
{
    return m_socket.TryWriteSome(data, size);
}

bool VpnCallbackStream::HasBufferedInput() const
{
    std::lock_guard lock(m_mutex);
    return m_callbackInput ? !m_input.empty() : m_socket.HasBufferedInput();
}

} // namespace tailgate::uwp::bg
