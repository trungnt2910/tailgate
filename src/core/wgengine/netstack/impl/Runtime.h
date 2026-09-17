#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

#include <lwip/tcp.h>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/crypto/Random.h>
#include <tailgate/types/nettype/TcpPortReservation.h>

#include "wgengine/netstack/port/Services.h"

namespace tailgate::wgengine::netstack::impl
{

// Owned by DI. Stack and stream entry points serialize all calls with Mutex(),
// including callbacks and destruction; the NO_SYS upstream API never runs concurrently.
class Runtime final
{
public:
    Runtime(std::shared_ptr<base::TimeProvider> timeProvider,
            std::shared_ptr<crypto::Random> random);
    ~Runtime();
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;

    [[nodiscard]] std::mutex& Mutex() noexcept;
    void Start();
    void ClearConnections() noexcept;
    void ClearFragments() noexcept;
    void Stop() noexcept;
    void Poll();
    [[nodiscard]] std::optional<base::TimeProvider::TimePoint> NextDeadline() const;
    // Attach only after converting a bound PCB to a listening PCB: conversion frees
    // the original PCB and copies its extension slots.
    [[nodiscard]] bool
    Track(tcp_pcb* pcb, void (*destroyed)(void*) = nullptr, void* context = nullptr) noexcept;
    [[nodiscard]] bool
    ReservePort(tcp_pcb* pcb,
                std::unique_ptr<types::nettype::TcpPortReservation> reservation) noexcept;
    [[nodiscard]] bool OwnsConnection(const ip_addr_t& local,
                                      std::uint16_t localPort,
                                      const ip_addr_t& remote,
                                      std::uint16_t remotePort,
                                      std::uint8_t interfaceIndex) const noexcept;
    [[nodiscard]] std::size_t ConnectionCount() const noexcept;
    [[nodiscard]] bool Started() const noexcept;

private:
    struct PcbSlot
    {
        Runtime* Owner = nullptr;
        tcp_pcb* Pcb = nullptr;
        void (*Destroyed)(void*) = nullptr;
        void* Context = nullptr;
        std::unique_ptr<types::nettype::TcpPortReservation> Reservation;
    };

    static void Destroyed(std::uint8_t id, void* data) noexcept;
    static err_t PassiveOpen(std::uint8_t id, tcp_pcb_listen* listener, tcp_pcb* child) noexcept;
    static std::uint32_t Now(void* context);
    static std::uint32_t Random(void* context);
    static std::uint32_t InitialSequence(void* context,
                                         const ip_addr_t* local,
                                         std::uint16_t localPort,
                                         const ip_addr_t* remote,
                                         std::uint16_t remotePort);

    std::shared_ptr<base::TimeProvider> m_timeProvider;
    std::shared_ptr<crypto::Random> m_random;
    std::mutex m_mutex;
    tailgate_lwip_services m_services;
    std::array<PcbSlot, MEMP_NUM_TCP_PCB + MEMP_NUM_TCP_PCB_LISTEN> m_pcbs{};
    std::uint8_t m_extensionId = LWIP_TCP_PCB_NUM_EXT_ARG_ID_INVALID;
    bool m_started = false;
};

} // namespace tailgate::wgengine::netstack::impl
