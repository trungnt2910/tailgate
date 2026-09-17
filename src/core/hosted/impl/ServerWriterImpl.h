#pragma once

#include <tailgate/base/EventLoop.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/hosted/ServerWriter.h>
#include <tailgate/wgengine/tstun/Device.h>

namespace tailgate::hosted::impl
{

class ServerWriterImpl final : public ServerWriter
{
public:
    ServerWriterImpl(tailgate::base::EventLoop& eventLoop,
                     tailgate::base::TimeProvider& timeProvider,
                     tailgate::wgengine::tstun::Device& device) noexcept;
    void Run(ServerSession& session,
             tailgate::base::ByteStream& stream,
             std::mutex& streamMutex,
             const std::atomic<bool>& stopping) override;
    void Wake() noexcept override;

private:
    void Process(ServerSession& session,
                 tailgate::base::ByteStream& stream,
                 std::mutex& streamMutex,
                 const std::atomic<bool>& stopping);

    tailgate::base::EventLoop& m_eventLoop;
    tailgate::base::TimeProvider& m_timeProvider;
    tailgate::wgengine::tstun::Device& m_device;
};

} // namespace tailgate::hosted::impl
