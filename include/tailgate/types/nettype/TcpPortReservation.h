#pragma once

#include <cstdint>
#include <memory>

#include <tailgate/net/IpAddress.h>

namespace tailgate::types::nettype
{

// Reserves a local TCP endpoint against the host stack without listening or
// connecting. Keep the lease until the userspace TCP PCB (including TIME_WAIT)
// is destroyed, not merely until its application stream is released.
class TcpPortReservation
{
public:
    virtual ~TcpPortReservation();
    [[nodiscard]] virtual std::uint16_t Port() const noexcept = 0;
};

class TcpPortReservationFactory
{
public:
    virtual ~TcpPortReservationFactory();
    [[nodiscard]] virtual std::unique_ptr<TcpPortReservation>
    TryReserve(const net::IpAddress& localAddress) = 0;
};

} // namespace tailgate::types::nettype
