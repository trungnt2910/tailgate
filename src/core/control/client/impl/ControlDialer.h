#pragma once

#include <memory>

#include <tailgate/base/ByteStream.h>
#include <tailgate/control/client/ControlClient.h>
#include <tailgate/types/nettype/TcpSocket.h>

namespace tailgate::control::client::impl
{

struct ControlDialOutcome
{
    std::unique_ptr<tailgate::types::nettype::TcpSocket> Stream;
    std::unique_ptr<tailgate::control::client::ControlClient> Client;
    bool UsedTls = false;
};

class ControlDialer
{
public:
    virtual ~ControlDialer() = default;

    [[nodiscard]] ControlDialOutcome Dial();

protected:
    [[nodiscard]] virtual std::unique_ptr<tailgate::types::nettype::TcpSocket> Open(bool tls) = 0;
    [[nodiscard]] virtual std::unique_ptr<tailgate::control::client::ControlClient>
    Establish(tailgate::base::ByteStream& stream) = 0;
};

} // namespace tailgate::control::client::impl
