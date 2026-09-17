#pragma once

#include <tailgate/types/nettype/TcpPortReservation.h>

namespace tailgate::uwp
{

class TcpPortReservationFactory final : public types::nettype::TcpPortReservationFactory
{
public:
    [[nodiscard]] std::unique_ptr<types::nettype::TcpPortReservation>
    TryReserve(const net::IpAddress& localAddress) override;
};

} // namespace tailgate::uwp
