#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/tstun/Device.h>

namespace tailgate::tests::fakes
{

class FakeDevice final : public tailgate::wgengine::tstun::Device
{
public:
    explicit FakeDevice(tailgate::types::nettype::TcpSocketFactory& socketFactory) noexcept
        : m_socketFactory(socketFactory)
    {
    }

    bool Open(const tailgate::wgengine::tstun::DeviceOptions& options) override
    {
        if (Opened || !OpenResult)
        {
            return false;
        }
        Options = options;
        Opened = true;
        return true;
    }

    tailgate::wgengine::tstun::DeviceReadResult TryRead(std::size_t) override
    {
        if (Closed)
        {
            return tailgate::wgengine::tstun::DeviceReadResult{
                .Result = tailgate::wgengine::tstun::DeviceIoResult::Closed,
                .Packet = {},
            };
        }
        if (Incoming.empty())
        {
            return {};
        }
        tailgate::wgengine::tstun::DeviceReadResult result = std::move(Incoming.front());
        Incoming.pop_front();
        return result;
    }

    tailgate::wgengine::tstun::DeviceIoResult
    TryWrite(const std::vector<std::uint8_t>& packet) override
    {
        if (Closed)
        {
            return tailgate::wgengine::tstun::DeviceIoResult::Closed;
        }
        if (WriteResult == tailgate::wgengine::tstun::DeviceIoResult::Complete)
        {
            Written.push_back(packet);
        }
        return WriteResult;
    }

    void SetWriteInterest(bool enabled) override
    {
        WriteInterest = enabled;
    }

    void Close() noexcept override
    {
        Closed = true;
    }

    std::unique_ptr<tailgate::types::nettype::TcpSocket>
    OpenTransportSocket(const tailgate::types::nettype::TcpSocketOptions& options) override
    {
        return m_socketFactory.OpenTcpSocket(options);
    }

    tailgate::wgengine::tstun::DeviceOptions Options;
    std::deque<tailgate::wgengine::tstun::DeviceReadResult> Incoming;
    std::vector<std::vector<std::uint8_t>> Written;
    tailgate::wgengine::tstun::DeviceIoResult WriteResult =
        tailgate::wgengine::tstun::DeviceIoResult::Complete;
    bool OpenResult = true;
    bool Opened = false;
    bool Closed = false;
    bool WriteInterest = false;

private:
    tailgate::types::nettype::TcpSocketFactory& m_socketFactory;
};

} // namespace tailgate::tests::fakes
