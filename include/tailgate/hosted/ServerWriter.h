#pragma once

#include <atomic>
#include <exception>
#include <mutex>

#include <tailgate/base/ByteStream.h>
#include <tailgate/hosted/ServerSession.h>

namespace tailgate::hosted
{

class ServerWriterOpenError final : public std::exception
{
public:
    [[nodiscard]] const char* what() const noexcept override;
};

class ServerWriter
{
public:
    virtual ~ServerWriter();
    virtual void Run(ServerSession& session,
                     tailgate::base::ByteStream& stream,
                     std::mutex& streamMutex,
                     const std::atomic<bool>& stopping) = 0;
    virtual void Wake() noexcept = 0;

protected:
    ServerWriter() = default;
};

} // namespace tailgate::hosted
