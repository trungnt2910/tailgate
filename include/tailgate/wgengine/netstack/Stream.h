#pragma once

#include <tailgate/base/ByteStream.h>

namespace tailgate::wgengine::netstack
{

enum class StreamState
{
    Connecting,
    Open,
    Closed,
    Failed,
};

class Stream : public base::ByteStream
{
public:
    ~Stream() override;
    [[nodiscard]] virtual StreamState State() const = 0;
    [[nodiscard]] virtual bool TryShutdownWrite() = 0;
    [[nodiscard]] virtual bool TryClose() = 0;
    virtual void Abort() noexcept = 0;
};

} // namespace tailgate::wgengine::netstack
