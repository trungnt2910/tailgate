#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

#include <tailgate/wgengine/tstun/Device.h>

namespace tailgate::tests::fakes
{

class FakeDevice final : public tailgate::wgengine::tstun::Device
{
public:
    bool Open(const tailgate::wgengine::tstun::DeviceOptions& options) override
    {
        if (Opened || !OpenResult)
        {
            return false;
        }
        Options = options;
        Opened = true;
        Closed = false;
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
        Opened = false;
        Closed = true;
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
};

} // namespace tailgate::tests::fakes
