#pragma once

#include <cstddef>
#include <memory>

#include <tailgate/base/ByteStream.h>

namespace tailgate::serve
{

enum class PeerApiConnectionStatus
{
    Ready,
    Closed,
};

class PeerApiConnection final
{
public:
    PeerApiConnection(tailgate::base::ByteStream& peer, tailgate::base::ByteStream& local);
    ~PeerApiConnection();
    PeerApiConnection(const PeerApiConnection&) = delete;
    PeerApiConnection& operator=(const PeerApiConnection&) = delete;

    [[nodiscard]] PeerApiConnectionStatus ProcessPeerInput();
    [[nodiscard]] PeerApiConnectionStatus ProcessLocalInput();
    [[nodiscard]] bool FlushPeerOutput();
    [[nodiscard]] bool FlushLocalOutput();
    [[nodiscard]] bool PeerOutputPending() const noexcept;
    [[nodiscard]] bool LocalOutputPending() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace tailgate::serve
