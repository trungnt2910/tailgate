#include <utility>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/PacketDispatch.h>

namespace
{

class Services final : public tailgate::ipn::ipnlocal::LocalServices
{
public:
    void SetNetworkConfig(const tailgate::types::netmap::NetworkConfig&) override
    {
        ++Updates;
    }

    void Stop() noexcept override
    {
        ++Stops;
    }

    bool HandleHostPacket(std::span<const std::uint8_t>) override
    {
        return true;
    }

    bool HandlePeerPacket(const tailgate::crypto::Bytes32&, std::span<const std::uint8_t>) override
    {
        return true;
    }

    void Poll() override
    {
        ++Polls;
    }

    std::vector<tailgate::ipn::ipnlocal::ServicePacket> TakeOutput(std::size_t maximum) override
    {
        Limit = maximum;
        return std::exchange(Output, {});
    }

    std::optional<tailgate::base::TimeProvider::TimePoint> NextDeadline() const override
    {
        return tailgate::base::TimeProvider::TimePoint(std::chrono::seconds(5));
    }

    std::vector<tailgate::ipn::ipnlocal::ServicePacket> Output;
    std::size_t Limit = 0;
    int Updates = 0;
    int Stops = 0;
    int Polls = 0;
};

} // namespace

TEST(Given_PacketDispatch, When_LocalServicesProducePackets_Then_EachReachesItsDestination)
{
    Services services;
    tailgate::crypto::Bytes32 peer{};
    peer.front() = 1;
    services.Output = {
        {.Peer = std::nullopt, .Bytes = {1}, .ForwardFromHost = false},
        {.Peer = peer, .Bytes = {2}, .ForwardFromHost = false},
        {.Peer = std::nullopt, .Bytes = {3}, .ForwardFromHost = true},
    };
    tailgate::ipn::ipnlocal::PacketDispatch dispatch(services);
    std::vector<std::uint8_t> host;
    std::vector<std::uint8_t> network;
    std::vector<std::uint8_t> peerBytes;
    tailgate::crypto::Bytes32 selectedPeer{};
    const tailgate::ipn::ipnlocal::PacketDelivery delivery{
        .Host =
            [&](auto bytes)
        {
            host = std::move(bytes);
            return true;
        },
        .Network =
            [&](const auto& bytes)
        {
            network = bytes;
        },
        .Peer =
            [&](const auto& key, const auto& bytes)
        {
            selectedPeer = key;
            peerBytes = bytes;
        },
    };

    dispatch.Poll(4, delivery);

    EXPECT_EQ(host, (std::vector<std::uint8_t>{1}));
    EXPECT_EQ(peerBytes, (std::vector<std::uint8_t>{2}));
    EXPECT_EQ(network, (std::vector<std::uint8_t>{3}));
    EXPECT_EQ(selectedPeer, peer);
    EXPECT_EQ(services.Limit, 4U);
    EXPECT_EQ(services.Stops, 0);
}

TEST(Given_PacketDispatch, When_DeliveryPathChanges_Then_ServiceInstanceAndDeadlineSurvive)
{
    Services services;
    tailgate::ipn::ipnlocal::PacketDispatch dispatch(services);
    int first = 0;
    int second = 0;
    const tailgate::ipn::ipnlocal::PacketDelivery oldPath{.Host = {},
                                                          .Network =
                                                              [&](const auto&)
                                                          {
                                                              ++first;
                                                          },
                                                          .Peer = {}};
    const tailgate::ipn::ipnlocal::PacketDelivery newPath{.Host = {},
                                                          .Network =
                                                              [&](const auto&)
                                                          {
                                                              ++second;
                                                          },
                                                          .Peer = {}};
    services.Output = {{.Peer = std::nullopt, .Bytes = {1}, .ForwardFromHost = true}};
    dispatch.Poll(1, oldPath);
    services.Output = {{.Peer = std::nullopt, .Bytes = {2}, .ForwardFromHost = true}};

    dispatch.Poll(1, newPath);

    EXPECT_EQ(first, 1);
    EXPECT_EQ(second, 1);
    EXPECT_EQ(services.Stops, 0);
    EXPECT_EQ(dispatch.NextDeadline(), services.NextDeadline());
}

TEST(Given_PacketDispatch, When_HostRejectsPacket_Then_RemainingBatchIsNotDelivered)
{
    Services services;
    services.Output = {
        {.Peer = std::nullopt, .Bytes = {1}, .ForwardFromHost = false},
        {.Peer = std::nullopt, .Bytes = {2}, .ForwardFromHost = false},
    };
    tailgate::ipn::ipnlocal::PacketDispatch dispatch(services);
    int deliveries = 0;
    const tailgate::ipn::ipnlocal::PacketDelivery delivery{.Host =
                                                               [&](auto)
                                                           {
                                                               ++deliveries;
                                                               return false;
                                                           },
                                                           .Network = {},
                                                           .Peer = {}};

    dispatch.Poll(2, delivery);

    EXPECT_EQ(deliveries, 1);
}
