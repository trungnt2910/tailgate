#pragma once

#include <tailgate/types/nettype/TcpPortReservation.h>

namespace tailgate::tests::fakes
{

class FakeTcpPortReservationFactory final : public types::nettype::TcpPortReservationFactory
{
    class Reservation final : public types::nettype::TcpPortReservation
    {
    public:
        Reservation(std::uint16_t port, std::shared_ptr<std::size_t> active)
            : m_port(port), m_active(std::move(active))
        {
            ++*m_active;
        }

        ~Reservation() override
        {
            --*m_active;
        }

        std::uint16_t Port() const noexcept override
        {
            return m_port;
        }

    private:
        std::uint16_t m_port;
        std::shared_ptr<std::size_t> m_active;
    };

public:
    std::unique_ptr<types::nettype::TcpPortReservation>
    TryReserve(const net::IpAddress& localAddress) override
    {
        LastAddress = localAddress;
        return Refuse ? nullptr : std::make_unique<Reservation>(NextPort++, Active);
    }

    bool Refuse = false;
    std::uint16_t NextPort = 49152;
    net::IpAddress LastAddress;
    std::shared_ptr<std::size_t> Active = std::make_shared<std::size_t>(0);
};

} // namespace tailgate::tests::fakes
