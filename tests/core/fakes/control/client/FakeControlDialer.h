#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "fakes/types/nettype/FakeTcpSocket.h"
#include "impl/ControlDialer.h"

namespace tailgate::tests::fakes
{

class FakeControlDialer final : public tailgate::control::client::impl::ControlDialer
{
public:
    bool PlaintextOpenFails = false;
    bool PlaintextEstablishFails = false;
    bool TlsOpenFails = false;
    bool TlsDialed = false;
    std::vector<std::string> Established;

protected:
    std::unique_ptr<tailgate::types::nettype::TcpSocket> Open(bool tls) override
    {
        if (tls)
        {
            TlsDialed = true;
            if (TlsOpenFails)
            {
                throw std::runtime_error("TLS port is blocked");
            }
            auto state = std::make_shared<FakeTcpSocketState>();
            state->Name = "tls";
            return std::make_unique<FakeTcpSocket>(std::move(state));
        }
        if (PlaintextOpenFails)
        {
            throw std::runtime_error("plaintext port is blocked");
        }
        auto state = std::make_shared<FakeTcpSocketState>();
        state->Name = "plaintext";
        return std::make_unique<FakeTcpSocket>(std::move(state));
    }

    std::unique_ptr<tailgate::control::client::ControlClient>
    Establish(tailgate::base::ByteStream& stream) override
    {
        const std::string& name = dynamic_cast<FakeTcpSocket&>(stream).Name();
        Established.push_back(name);
        if (name == "plaintext" && PlaintextEstablishFails)
        {
            throw std::runtime_error("upgrade was tampered with");
        }
        return {};
    }
};

} // namespace tailgate::tests::fakes
