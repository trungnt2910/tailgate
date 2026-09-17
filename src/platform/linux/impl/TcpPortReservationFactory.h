#pragma once

#include <tailgate/types/nettype/TcpPortReservation.h>

namespace tailgate::linux_frontend::impl
{

class TcpPortReservationFactory final : public types::nettype::TcpPortReservationFactory
{
public:
    [[nodiscard]] std::unique_ptr<types::nettype::TcpPortReservation>
    TryReserve(const net::IpAddress& localAddress) override;
};

} // namespace tailgate::linux_frontend::impl
