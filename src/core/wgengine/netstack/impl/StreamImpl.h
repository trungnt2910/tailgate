#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <vector>

#include <lwip/tcp.h>

#include <tailgate/wgengine/netstack/Stream.h>

#include "Runtime.h"

namespace tailgate::wgengine::netstack::impl
{

// Created by Stack's connection factory while holding the runtime lock. User calls
// acquire that same lock; raw callbacks only update this connection's bounded state.
class StreamImpl final : public Stream
{
public:
    StreamImpl(std::shared_ptr<Runtime> runtime, tcp_pcb* pcb, StreamState state);
    ~StreamImpl() override;
    [[nodiscard]] std::optional<std::size_t> TryWriteSome(const std::uint8_t* data,
                                                          std::size_t size) override;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    TryReadSome(std::size_t maximumBytes) override;
    [[nodiscard]] bool HasBufferedInput() const override;
    [[nodiscard]] StreamState State() const override;
    [[nodiscard]] bool TryShutdownWrite() override;
    [[nodiscard]] bool TryClose() override;
    void Abort() noexcept override;

    static err_t Connected(void* context, tcp_pcb* pcb, err_t error) noexcept;

private:
    void InstallCallbacks() noexcept;
    static void Destroyed(void* context) noexcept;
    static void Failed(void* context, err_t error) noexcept;
    static err_t Received(void* context, tcp_pcb* pcb, pbuf* buffer, err_t error) noexcept;

    std::shared_ptr<Runtime> m_runtime;
    tcp_pcb* m_pcb;
    StreamState m_state;
    std::deque<std::vector<std::uint8_t>> m_received;
    std::size_t m_receiveOffset = 0;
    std::size_t m_receiveBytes = 0;
    bool m_readEof = false;
    bool m_writeEof = false;
};

} // namespace tailgate::wgengine::netstack::impl
