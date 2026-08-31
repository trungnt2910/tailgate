#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::tests::fakes
{

struct FakeTcpSocketState
{
    std::string Name;
    std::deque<std::vector<std::uint8_t>> Incoming;
    std::vector<std::uint8_t> Written;
    bool ReadWouldBlock = false;
    bool WriteWouldBlock = false;
    bool ReadNeedsWrite = false;
    bool WriteNeedsRead = false;
    bool WriteInterest = false;
    bool NonBlocking = false;
    bool Closed = false;
    std::optional<std::chrono::seconds> ReadTimeout;
};

class FakeTcpSocket final : public tailgate::types::nettype::TcpSocket
{
public:
    explicit FakeTcpSocket(std::shared_ptr<FakeTcpSocketState> state) : m_state(std::move(state))
    {
    }

    [[nodiscard]] const std::string& Name() const noexcept
    {
        return m_state->Name;
    }

    std::optional<std::size_t> TryWriteSome(const std::uint8_t* data, std::size_t size) override
    {
        if (m_state->WriteWouldBlock)
        {
            return std::nullopt;
        }
        if (m_state->Closed)
        {
            return 0;
        }
        m_state->Written.insert(m_state->Written.end(), data, data + size);
        return size;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maximumSize) override
    {
        if (m_state->Closed)
        {
            return std::vector<std::uint8_t>{};
        }
        if (m_state->ReadWouldBlock || m_state->Incoming.empty())
        {
            return std::nullopt;
        }
        std::vector<std::uint8_t>& incoming = m_state->Incoming.front();
        const std::size_t size = std::min(maximumSize, incoming.size());
        std::vector<std::uint8_t> result(incoming.begin(),
                                         incoming.begin() + static_cast<std::ptrdiff_t>(size));
        incoming.erase(incoming.begin(), incoming.begin() + static_cast<std::ptrdiff_t>(size));
        if (incoming.empty())
        {
            m_state->Incoming.pop_front();
        }
        return result;
    }

    bool HasBufferedInput() const override
    {
        return !m_state->Incoming.empty();
    }

    bool ReadNeedsWrite() const override
    {
        return m_state->ReadNeedsWrite;
    }

    bool WriteNeedsRead() const override
    {
        return m_state->WriteNeedsRead;
    }

    void SetReadTimeout(std::optional<std::chrono::seconds> timeout) override
    {
        m_state->ReadTimeout = timeout;
    }

    void SetWriteInterest(bool enabled) override
    {
        m_state->WriteInterest = enabled;
    }

    void SetNonBlocking(bool enabled) override
    {
        m_state->NonBlocking = enabled;
    }

    void Close() noexcept override
    {
        m_state->Closed = true;
    }

private:
    std::shared_ptr<FakeTcpSocketState> m_state;
};

class FakeTcpSocketFactory final : public tailgate::types::nettype::TcpSocketFactory
{
public:
    std::unique_ptr<tailgate::types::nettype::TcpSocket>
    OpenTcpSocket(const tailgate::types::nettype::TcpSocketOptions& options) override
    {
        if (!Open)
        {
            throw std::logic_error("The fake TCP socket factory is not configured.");
        }
        return Open(options);
    }

    std::function<std::unique_ptr<tailgate::types::nettype::TcpSocket>(
        const tailgate::types::nettype::TcpSocketOptions&)>
        Open;
};

} // namespace tailgate::tests::fakes
