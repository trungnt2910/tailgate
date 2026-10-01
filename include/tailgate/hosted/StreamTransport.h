#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <vector>

#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::hosted
{

// A single ordered relay stream, independent of VPN callback framing. The node
// worker serializes access; asynchronous platform completions only post readiness.
class StreamTransport final
{
public:
    StreamTransport(std::unique_ptr<types::nettype::TcpSocket> socket, Decoder decoder);
    ~StreamTransport();
    [[nodiscard]] bool Queue(std::vector<std::uint8_t> bytes);
    // Bounded work. MoreWork means buffered work remains and another turn is needed.
    [[nodiscard]] bool Flush(std::size_t maximumWrites);
    [[nodiscard]] std::vector<Frame> Receive(std::size_t maximumReads, std::size_t maximumFrames);
    [[nodiscard]] bool HasBufferedInput() const;
    void Close() noexcept;

private:
    void UpdateWriteInterest();
    static constexpr std::size_t MaximumQueuedBytes = 4U * 1024U * 1024U;
    static constexpr std::size_t MaximumReadSize = 64U * 1024U;
    std::unique_ptr<types::nettype::TcpSocket> m_socket;
    Decoder m_decoder;
    std::deque<std::vector<std::uint8_t>> m_output;
    std::size_t m_queuedBytes = 0;
    std::size_t m_offset = 0;
    bool m_moreFrames = false;
    bool m_moreReads = false;
    bool m_closed = false;
};

} // namespace tailgate::hosted
