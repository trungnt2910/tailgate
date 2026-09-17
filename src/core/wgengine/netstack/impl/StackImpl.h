#pragma once

#include <array>
#include <deque>
#include <memory>

#include <lwip/netif.h>
#include <lwip/raw.h>
#include <lwip/tcp.h>

#include <tailgate/wgengine/netstack/Stack.h>

#include "Runtime.h"

namespace tailgate::wgengine::netstack::impl
{

class StackImpl final : public Stack
{
public:
    StackImpl(std::shared_ptr<Runtime> runtime,
              types::nettype::TcpPortReservationFactory& portReservations);
    ~StackImpl() override;
    void Start(const Configuration& configuration) override;
    void Stop() noexcept override;
    void InvalidatePeerPackets() override;
    void Listen(const TcpEndpoint& endpoint) override;
    [[nodiscard]] std::unique_ptr<Stream> Connect(const TcpEndpoint& endpoint) override;
    [[nodiscard]] std::unique_ptr<Stream> TakeAccepted() override;
    [[nodiscard]] bool Input(PacketPath path, std::span<const std::uint8_t> packet) override;
    [[nodiscard]] std::vector<OutputPacket> TakeOutput(std::size_t maximumPackets) override;
    [[nodiscard]] bool HasOutput(PacketPath path) const override;
    void Poll() override;
    [[nodiscard]] std::optional<base::TimeProvider::TimePoint> NextDeadline() const override;

private:
    struct Interface
    {
        netif Native{};
        StackImpl* Owner = nullptr;
        PacketPath Path = PacketPath::Host;
        bool Added = false;
    };

    void RequireStarted() const;
    void AddInterface(Interface& interface, const InterfaceAddresses& addresses);
    void AddDemultiplexer();
    void RemoveDemultiplexer() noexcept;
    err_t QueueOutput(PacketPath path, pbuf* packet) noexcept;
    static std::uint8_t
    DemultiplexInput(void* context, raw_pcb*, pbuf* packet, const ip_addr_t*) noexcept;
    static err_t InitializeInterface(netif* interface) noexcept;
    static err_t Output4(netif* interface, pbuf* packet, const ip4_addr_t*) noexcept;
    static err_t Output6(netif* interface, pbuf* packet, const ip6_addr_t*) noexcept;
    static err_t Output(netif* interface, pbuf* packet) noexcept;
    static err_t Accepted(void* context, tcp_pcb* pcb, err_t error) noexcept;

    std::shared_ptr<Runtime> m_runtime;
    types::nettype::TcpPortReservationFactory& m_portReservations;
    Interface m_service;
    Interface m_node;
    std::array<raw_pcb*, MEMP_NUM_RAW_PCB> m_demultiplexer{};
    Configuration m_configuration;
    std::deque<OutputPacket> m_output;
    std::deque<std::unique_ptr<Stream>> m_accepted;
    std::size_t m_outputBytes = 0;
    bool m_started = false;
    bool m_discardOutput = false;
};

} // namespace tailgate::wgengine::netstack::impl
