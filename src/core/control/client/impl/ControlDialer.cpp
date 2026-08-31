#include "ControlDialer.h"

#include <exception>
#include <string>
#include <utility>

#include <tailgate/base/Logging.h>

namespace tailgate::control::client::impl
{

ControlDialOutcome ControlDialer::Dial()
{
    try
    {
        std::unique_ptr<tailgate::types::nettype::TcpSocket> stream = Open(false);
        std::unique_ptr<tailgate::control::client::ControlClient> client = Establish(*stream);
        return ControlDialOutcome{
            .Stream = std::move(stream),
            .Client = std::move(client),
            .UsedTls = false,
        };
    }
    catch (const std::exception& error)
    {
        tailgate::base::Log(tailgate::base::LogLevel::Warning,
                            "control",
                            std::string("plaintext control connection failed (") + error.what() +
                                "); falling back to TLS");
    }
    std::unique_ptr<tailgate::types::nettype::TcpSocket> stream = Open(true);
    std::unique_ptr<tailgate::control::client::ControlClient> client = Establish(*stream);
    return ControlDialOutcome{
        .Stream = std::move(stream),
        .Client = std::move(client),
        .UsedTls = true,
    };
}

} // namespace tailgate::control::client::impl
