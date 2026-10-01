#pragma once

#include <utility>

#include <tailgate/ipn/ipnlocal/LocalServices.h>

namespace tailgate::tests::fakes
{

class FakeLocalServices final : public ipn::ipnlocal::LocalServices
{
public:
    void SetNetworkConfig(const types::netmap::NetworkConfig&) override
    {
        ++Updates;
    }

    void Stop() noexcept override
    {
        ++Stops;
    }

    bool HandleHostPacket(std::span<const std::uint8_t>) override
    {
        return ConsumeHost;
    }

    bool HandlePeerPacket(const crypto::Bytes32& peer, std::span<const std::uint8_t>) override
    {
        AuthenticatedPeer = peer;
        return ConsumePeer;
    }

    void Poll() override
    {
        ++Polls;
    }

    std::vector<ipn::ipnlocal::ServicePacket> TakeOutput(std::size_t) override
    {
        return std::exchange(Output, {});
    }

    std::optional<base::TimeProvider::TimePoint> NextDeadline() const override
    {
        return Deadline;
    }

    bool ConsumeHost = false;
    bool ConsumePeer = false;
    int Updates = 0;
    int Stops = 0;
    int Polls = 0;
    crypto::Bytes32 AuthenticatedPeer{};
    std::optional<base::TimeProvider::TimePoint> Deadline;
    std::vector<ipn::ipnlocal::ServicePacket> Output;
};

} // namespace tailgate::tests::fakes
