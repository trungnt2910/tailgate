#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <numeric>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>

#include <tailgate/net/packet/Ip.h>
#include <tailgate/wgengine/netstack/Error.h>
#include <tailgate/wgengine/netstack/Stack.h>

#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/net/FragmentedPackets.h"

namespace tailgate::tests
{
namespace netstack = wgengine::netstack;

enum class FragmentMode
{
    Ipv4,
    Ipv6,
    Ipv6DestinationOptions,
};

class Given_NetStack : public testing::Test, public testing::WithParamInterface<FragmentMode>
{
protected:
    Given_NetStack()
    {
        fakes::InstallFakeNetworkBindings(m_injector);
        m_configuration.Service.Ipv4 = net::IpAddress::Parse("192.0.2.1");
        m_configuration.Service.Ipv6 = net::IpAddress::Parse("2001:db8::1");
        m_configuration.Node.Ipv4 = net::IpAddress::Parse("192.0.2.2");
        m_configuration.Node.Ipv6 = net::IpAddress::Parse("2001:db8::2");
        m_stack = &m_injector.create<netstack::Stack&>();
        m_stack->Start(m_configuration);
        m_bytes.resize(TransferSize);
        std::iota(m_bytes.begin(), m_bytes.end(), std::uint8_t{});
        m_received.reserve(m_bytes.size());
    }

    // Both endpoints use the production TCP implementation. The explicit test
    // wire joins two interfaces without OS sockets or a second global lwIP runtime.
    bool Deliver()
    {
        const auto packets = m_stack->TakeOutput(128);
        bool accepted = true;
        for (const auto& packet : packets)
        {
            const auto incoming = packet.Path == netstack::PacketPath::Peer
                                      ? netstack::PacketPath::Host
                                      : netstack::PacketPath::Peer;
            accepted = m_stack->Input(incoming, packet.Bytes) && accepted;
        }
        return accepted;
    }

    void Establish(bool ipv6)
    {
        const netstack::TcpEndpoint endpoint{.Address = ipv6 ? *m_configuration.Service.Ipv6
                                                             : m_configuration.Service.Ipv4,
                                             .Port = 8080};
        m_stack->Listen(endpoint);
        m_client = m_stack->Connect(endpoint);
        ASSERT_TRUE(m_stack->HasOutput(netstack::PacketPath::Peer));
        ASSERT_TRUE(Deliver());
        ASSERT_TRUE(m_stack->HasOutput(netstack::PacketPath::Host));
        ASSERT_TRUE(Deliver());
        ASSERT_TRUE(Deliver());
        m_server = m_stack->TakeAccepted();
        ASSERT_NE(m_server, nullptr);
    }

    di::Injector m_injector;
    netstack::Configuration m_configuration;
    netstack::Stack* m_stack = nullptr;
    std::unique_ptr<netstack::Stream> m_client;
    std::unique_ptr<netstack::Stream> m_server;

    bool UseIpv6() const
    {
        return GetParam() != FragmentMode::Ipv4;
    }

    netstack::TcpEndpoint Endpoint() const
    {
        return {.Address = UseIpv6() ? *m_configuration.Service.Ipv6 : m_configuration.Service.Ipv4,
                .Port = 8080};
    }

    bool AdvanceDeadline()
    {
        auto& time =
            dynamic_cast<fakes::FakeTimeProvider&>(m_injector.create<base::TimeProvider&>());
        const auto deadline = m_stack->NextDeadline();
        if (!deadline || *deadline < time.Now())
        {
            return false;
        }
        // Drive a discrete virtual-clock event, not a real-time polling wait.
        time.Set(*deadline);
        m_stack->Poll();
        return true;
    }

    bool AdvanceUntilOutput(netstack::PacketPath path)
    {
        constexpr std::size_t MaximumRecoveryEvents = 128;
        for (std::size_t event = 0; event < MaximumRecoveryEvents; ++event)
        {
            if (m_stack->HasOutput(path))
            {
                return true;
            }
            if (!AdvanceDeadline())
            {
                return false;
            }
        }
        return m_stack->HasOutput(path);
    }

    void SendAvailable()
    {
        if (m_sent == m_bytes.size())
        {
            return;
        }
        const auto written =
            m_client->TryWriteSome(m_bytes.data() + m_sent, m_bytes.size() - m_sent);
        if (written)
        {
            m_sent += *written;
        }
        else
        {
            m_writeBlocked = true;
        }
    }

    bool DeliverObserved(bool dropWindowUpdates = false)
    {
        constexpr std::size_t PacketBatch = 128;
        constexpr std::uint8_t TcpProtocol = 6;
        constexpr std::size_t TcpHeaderLength = 20;
        constexpr std::size_t DataOffsetPosition = 12;
        constexpr std::size_t WindowOffset = 14;
        bool accepted = true;
        for (const auto& packet : m_stack->TakeOutput(PacketBatch))
        {
            const auto envelope = net::packet::ParseIpEnvelope(packet.Bytes);
            if (packet.Path == netstack::PacketPath::Peer && m_zeroWindow &&
                m_droppedUpdates != 0 && envelope && envelope->Protocol == TcpProtocol &&
                packet.Bytes.size() >= envelope->PayloadOffset + TcpHeaderLength)
            {
                const auto headerLength =
                    static_cast<std::size_t>(
                        packet.Bytes[envelope->PayloadOffset + DataOffsetPosition] >> 4) *
                    4;
                m_persistProbe = m_persistProbe ||
                                 packet.Bytes.size() == envelope->PayloadOffset + headerLength + 1;
            }
            if (packet.Path == netstack::PacketPath::Host && envelope &&
                envelope->Protocol == TcpProtocol &&
                packet.Bytes.size() >= envelope->PayloadOffset + TcpHeaderLength)
            {
                const auto offset = envelope->PayloadOffset + WindowOffset;
                const bool zero = packet.Bytes[offset] == 0 && packet.Bytes[offset + 1] == 0;
                m_zeroWindow = m_zeroWindow || zero;
                if (dropWindowUpdates && !zero)
                {
                    ++m_droppedUpdates;
                    continue;
                }
            }
            const auto path = packet.Path == netstack::PacketPath::Peer
                                  ? netstack::PacketPath::Host
                                  : netstack::PacketPath::Peer;
            accepted = m_stack->Input(path, packet.Bytes) && accepted;
        }
        return accepted;
    }

    bool DrainServer()
    {
        constexpr std::size_t MaximumReadChunks = 128;
        constexpr std::size_t ReadSize = 16U * 1024U;
        for (std::size_t chunk = 0; chunk < MaximumReadChunks; ++chunk)
        {
            const auto part = m_server->TryReadSome(ReadSize);
            if (!part)
            {
                return true;
            }
            if (part->empty() || part->size() > m_bytes.size() - m_received.size())
            {
                return false;
            }
            m_received.insert(m_received.end(), part->begin(), part->end());
        }
        return !m_server->HasBufferedInput();
    }

    bool AdvanceIfIdle()
    {
        return m_stack->HasOutput(netstack::PacketPath::Peer) ||
               m_stack->HasOutput(netstack::PacketPath::Host) || AdvanceDeadline();
    }

    bool FillReceiveWindow()
    {
        for (std::size_t step = 0; step < MaximumTransferSteps && !m_zeroWindow; ++step)
        {
            SendAvailable();
            if (!DeliverObserved() || !DeliverObserved() || !AdvanceIfIdle())
            {
                return false;
            }
        }
        return m_zeroWindow;
    }

    bool CompleteTransfer()
    {
        for (std::size_t step = 0; step < MaximumTransferSteps; ++step)
        {
            SendAvailable();
            if (!DeliverObserved() || !DrainServer() || !DeliverObserved())
            {
                return false;
            }
            if (m_sent == m_bytes.size() && m_received.size() == m_bytes.size())
            {
                return true;
            }
            if (!AdvanceIfIdle())
            {
                return false;
            }
        }
        return false;
    }

    static constexpr std::size_t TransferSize = 1024U * 1024U;
    static constexpr std::size_t MaximumTransferSteps = 4096;
    std::vector<std::uint8_t> m_bytes;
    std::vector<std::uint8_t> m_received;
    std::size_t m_sent = 0;
    std::size_t m_droppedUpdates = 0;
    bool m_zeroWindow = false;
    bool m_writeBlocked = false;
    bool m_persistProbe = false;

    void Prepare(bool fromPeer)
    {
        const bool ipv6 = GetParam() != FragmentMode::Ipv4;
        ASSERT_NO_FATAL_FAILURE(Establish(ipv6));
        auto& sender = fromPeer ? m_server : m_client;
        ASSERT_EQ(sender->TryWriteSome(payload.data(), payload.size()), payload.size());
        auto packets = m_stack->TakeOutput(128);
        ASSERT_EQ(packets.size(), 1U);
        original = std::move(packets.front().Bytes);
        if (GetParam() == FragmentMode::Ipv6DestinationOptions)
        {
            fakes::AddIpv6DestinationOptions(original);
        }
        fragments = ipv6 ? fakes::FragmentIpv6(original) : fakes::FragmentIpv4(original);
        ASSERT_GE(fragments.size(), 3U);
    }

    bool DeliverFragments(netstack::PacketPath path)
    {
        bool delivered = true;
        for (auto fragment = fragments.rbegin(); fragment != fragments.rend(); ++fragment)
        {
            delivered = m_stack->Input(path, *fragment) && delivered;
        }
        return delivered;
    }

    void PrepareIdleFragments()
    {
        ASSERT_NO_FATAL_FAILURE(Prepare(true));
        m_client->Abort();
        m_server->Abort();
        (void)m_stack->TakeOutput(128);
        m_stack->Poll();
        ASSERT_FALSE(m_stack->NextDeadline());
    }

    const std::vector<std::uint8_t> payload = std::vector<std::uint8_t>(64, 42);
    std::vector<std::uint8_t> original;
    std::vector<std::vector<std::uint8_t>> fragments;
};

TEST_F(Given_NetStack, When_OnlyListenersExist_Then_IdleMaintenanceNeedsNoWakeup)
{
    m_stack->Listen({.Address = m_configuration.Service.Ipv4, .Port = 8080});
    m_stack->Listen({.Address = *m_configuration.Service.Ipv6, .Port = 8080});
    auto& time = dynamic_cast<fakes::FakeTimeProvider&>(m_injector.create<base::TimeProvider&>());
    bool requestedWakeup = false;

    for (unsigned heartbeat = 0; heartbeat < 3; ++heartbeat)
    {
        time.Advance(std::chrono::seconds(20));
        m_stack->Poll();
        requestedWakeup |= m_stack->NextDeadline().has_value();
    }

    EXPECT_FALSE(requestedWakeup);
    EXPECT_TRUE(m_stack->TakeOutput(128).empty());
}

TEST_P(Given_NetStack, When_TcpStartsAfterLongIdle_Then_RetransmissionTimerResumes)
{
    auto& time = dynamic_cast<fakes::FakeTimeProvider&>(m_injector.create<base::TimeProvider&>());
    time.Advance(std::chrono::hours(24 * 60));
    ASSERT_FALSE(m_stack->NextDeadline());
    m_stack->Listen(Endpoint());

    m_client = m_stack->Connect(Endpoint());
    const auto initial = m_stack->TakeOutput(128);
    const bool retransmitted = AdvanceUntilOutput(netstack::PacketPath::Peer);
    const bool deliveredSyn = Deliver();
    const bool deliveredReply = Deliver();
    const bool deliveredAcknowledgement = Deliver();
    auto accepted = m_stack->TakeAccepted();

    EXPECT_EQ(initial.size(), 1U);
    EXPECT_TRUE(retransmitted);
    EXPECT_TRUE(deliveredSyn);
    EXPECT_TRUE(deliveredReply);
    EXPECT_TRUE(deliveredAcknowledgement);
    EXPECT_EQ(m_client->State(), netstack::StreamState::Open);
    EXPECT_NE(accepted, nullptr);
}

TEST_P(Given_NetStack, When_IdleFragmentsComplete_Then_MaintenanceWakeupsStop)
{
    ASSERT_NO_FATAL_FAILURE(PrepareIdleFragments());
    ASSERT_TRUE(m_stack->Input(netstack::PacketPath::Peer, fragments.back()));
    ASSERT_TRUE(m_stack->NextDeadline());
    bool delivered = true;

    for (std::size_t index = 0; index + 1 < fragments.size(); ++index)
    {
        delivered = m_stack->Input(netstack::PacketPath::Peer, fragments[index]) && delivered;
    }
    const auto output = m_stack->TakeOutput(128);

    EXPECT_TRUE(delivered);
    EXPECT_EQ(output.size(), 1U);
    EXPECT_FALSE(m_stack->NextDeadline());
}

TEST_P(Given_NetStack, When_IdleFragmentsExpire_Then_WakeupsStopAndLateFragmentsCannotComplete)
{
    ASSERT_NO_FATAL_FAILURE(PrepareIdleFragments());
    auto& time = dynamic_cast<fakes::FakeTimeProvider&>(m_injector.create<base::TimeProvider&>());
    time.Advance(std::chrono::hours(24 * 60));
    // A noninitial fragment avoids an ICMP timeout response obscuring the reassembly check.
    ASSERT_TRUE(m_stack->Input(netstack::PacketPath::Peer, fragments.back()));
    ASSERT_TRUE(m_stack->NextDeadline());
    const auto started = time.Now();
    const auto lifetime = std::chrono::seconds(UseIpv6() ? IPV6_REASS_MAXAGE : IP_REASS_MAXAGE);
    const auto tick =
        std::chrono::milliseconds(UseIpv6() ? IP6_REASS_TMR_INTERVAL : IP_TMR_INTERVAL);
    const auto limit = started + lifetime + 2 * tick;
    bool delivered = true;

    while (m_stack->NextDeadline() && time.Now() < limit)
    {
        if (!AdvanceDeadline())
        {
            break;
        }
    }
    const auto elapsed = time.Now() - started;
    const bool expired = !m_stack->NextDeadline();
    for (std::size_t index = 0; index + 1 < fragments.size(); ++index)
    {
        delivered = m_stack->Input(netstack::PacketPath::Peer, fragments[index]) && delivered;
    }

    EXPECT_TRUE(expired);
    EXPECT_GE(elapsed, lifetime);
    EXPECT_LE(elapsed, lifetime + tick);
    EXPECT_TRUE(delivered);
    EXPECT_TRUE(m_stack->TakeOutput(128).empty());
    EXPECT_TRUE(m_stack->NextDeadline());
}

TEST_P(Given_NetStack, When_PendingFragmentsAreInvalidated_Then_MaintenanceWakeupsStop)
{
    ASSERT_NO_FATAL_FAILURE(PrepareIdleFragments());
    ASSERT_TRUE(m_stack->Input(netstack::PacketPath::Peer, fragments.back()));
    ASSERT_TRUE(m_stack->NextDeadline());

    m_stack->InvalidatePeerPackets();

    EXPECT_FALSE(m_stack->NextDeadline());
}

TEST_F(Given_NetStack, When_Ipv4HandshakeCompletes_Then_StreamsExchangeBytes)
{
    ASSERT_NO_FATAL_FAILURE(Establish(false));
    const std::vector<std::uint8_t> m_bytes{1, 2, 3, 4};

    const auto written = m_client->TryWriteSome(m_bytes.data(), m_bytes.size());
    const bool delivered = Deliver();
    const auto m_received = m_server->TryReadSome(m_bytes.size());

    EXPECT_EQ(m_client->State(), netstack::StreamState::Open);
    EXPECT_EQ(m_server->State(), netstack::StreamState::Open);
    EXPECT_EQ(written, m_bytes.size());
    EXPECT_TRUE(delivered);
    EXPECT_EQ(m_received, m_bytes);
}

TEST_F(Given_NetStack, When_Ipv6HandshakeCompletes_Then_StreamsExchangeBytes)
{
    ASSERT_NO_FATAL_FAILURE(Establish(true));
    const std::vector<std::uint8_t> m_bytes{5, 6, 7, 8};

    const auto written = m_server->TryWriteSome(m_bytes.data(), m_bytes.size());
    const bool delivered = Deliver();
    const auto m_received = m_client->TryReadSome(m_bytes.size());

    EXPECT_EQ(m_client->State(), netstack::StreamState::Open);
    EXPECT_EQ(m_server->State(), netstack::StreamState::Open);
    EXPECT_EQ(written, m_bytes.size());
    EXPECT_TRUE(delivered);
    EXPECT_EQ(m_received, m_bytes);
}

TEST_F(Given_NetStack, When_WriteHalfCloses_Then_PeerCanStillReply)
{
    ASSERT_NO_FATAL_FAILURE(Establish(false));
    const std::vector<std::uint8_t> m_bytes{42};

    const bool shutdown = m_client->TryShutdownWrite();
    const bool finDelivered = Deliver();
    const auto eof = m_server->TryReadSome(1);
    const auto written = m_server->TryWriteSome(m_bytes.data(), m_bytes.size());
    const bool dataDelivered = Deliver();
    const auto m_received = m_client->TryReadSome(1);

    EXPECT_TRUE(shutdown);
    EXPECT_TRUE(finDelivered);
    EXPECT_EQ(eof, std::vector<std::uint8_t>{});
    EXPECT_EQ(written, m_bytes.size());
    EXPECT_TRUE(dataDelivered);
    EXPECT_EQ(m_received, m_bytes);
}

TEST_F(Given_NetStack, When_StopRetiresEstablishedConnections_Then_RestartCanListenAgain)
{
    ASSERT_NO_FATAL_FAILURE(Establish(false));
    const netstack::TcpEndpoint endpoint{.Address = m_configuration.Service.Ipv4, .Port = 8080};

    m_stack->Stop();
    m_stack->Start(m_configuration);
    m_stack->Listen(endpoint);
    auto replacement = m_stack->Connect(endpoint);

    EXPECT_EQ(m_client->State(), netstack::StreamState::Failed);
    EXPECT_EQ(m_server->State(), netstack::StreamState::Failed);
    EXPECT_EQ(replacement->State(), netstack::StreamState::Connecting);
    EXPECT_TRUE(m_stack->HasOutput(netstack::PacketPath::Peer));
}

TEST_F(Given_NetStack, When_HostCannotReservePort_Then_NoSynIsEmitted)
{
    auto& reservations = m_injector.create<fakes::FakeTcpPortReservationFactory&>();
    reservations.Refuse = true;
    const netstack::TcpEndpoint endpoint{.Address = m_configuration.Service.Ipv4, .Port = 8080};
    std::optional<netstack::Error> error;

    try
    {
        m_client = m_stack->Connect(endpoint);
    }
    catch (const netstack::Exception& exception)
    {
        error = exception.Reason();
    }

    EXPECT_EQ(error, netstack::Error::ConnectionFailed);
    EXPECT_FALSE(m_stack->HasOutput(netstack::PacketPath::Peer));
    EXPECT_EQ(*reservations.Active, 0U);
}

TEST_F(Given_NetStack, When_StreamClosesBeforeTcpLifetimeEnds_Then_PortReservationSurvivesHandle)
{
    ASSERT_NO_FATAL_FAILURE(Establish(false));
    auto& reservations = m_injector.create<fakes::FakeTcpPortReservationFactory&>();
    ASSERT_EQ(*reservations.Active, 1U);

    const bool closed = m_client->TryClose();
    m_client.reset();
    const auto duringFinWait = *reservations.Active;
    m_stack->Stop();

    EXPECT_TRUE(closed);
    EXPECT_EQ(duringFinWait, 1U);
    EXPECT_EQ(*reservations.Active, 0U);
    EXPECT_EQ(reservations.LastAddress, m_configuration.Node.Ipv4);
}

TEST_F(Given_NetStack, When_UnownedPeerTcpArrives_Then_PacketReturnsToHostWithoutReset)
{
    ASSERT_NO_FATAL_FAILURE(Establish(false));
    const std::uint8_t byte = 42;
    ASSERT_EQ(m_server->TryWriteSome(&byte, 1), 1U);
    const auto packets = m_stack->TakeOutput(128);
    ASSERT_EQ(packets.size(), 1U);
    m_client->Abort();
    (void)m_stack->TakeOutput(128);

    const auto accepted = m_stack->Input(netstack::PacketPath::Peer, packets.front().Bytes);
    const auto output = m_stack->TakeOutput(128);
    ASSERT_EQ(output.size(), 1U);

    EXPECT_TRUE(accepted);
    EXPECT_EQ(output.size(), 1U);
    EXPECT_EQ(output.front().Path, netstack::PacketPath::Host);
    EXPECT_EQ(output.front().Bytes, packets.front().Bytes);
}

TEST_F(Given_NetStack, When_Ipv6TcpHasDestinationOptions_Then_OwnedFlowStillReceivesData)
{
    ASSERT_NO_FATAL_FAILURE(Establish(true));
    const std::uint8_t byte = 42;
    ASSERT_EQ(m_server->TryWriteSome(&byte, 1), 1U);
    auto packets = m_stack->TakeOutput(128);
    ASSERT_EQ(packets.size(), 1U);
    auto& packet = packets.front().Bytes;
    constexpr std::size_t Ipv6HeaderLength = 40;
    constexpr std::uint8_t DestinationOptions = 60;
    constexpr std::uint8_t TcpProtocol = 6;
    constexpr std::size_t ExtensionLength = 8;
    ASSERT_GE(packet.size(), Ipv6HeaderLength);
    packet.insert(packet.begin() + Ipv6HeaderLength, ExtensionLength, 0);
    packet[6] = DestinationOptions;
    packet[Ipv6HeaderLength] = TcpProtocol;
    const auto payloadLength = packet.size() - Ipv6HeaderLength;
    packet[4] = static_cast<std::uint8_t>(payloadLength >> 8);
    packet[5] = static_cast<std::uint8_t>(payloadLength);

    const auto accepted = m_stack->Input(netstack::PacketPath::Peer, packet);
    const auto m_received = m_client->TryReadSome(1);

    EXPECT_TRUE(accepted);
    EXPECT_EQ(m_received, (std::vector<std::uint8_t>{byte}));
    EXPECT_FALSE(m_stack->HasOutput(netstack::PacketPath::Host));
}

TEST_P(Given_NetStack, When_InitialSynIsLost_Then_DeadlineRetransmissionConnects)
{
    m_stack->Listen(Endpoint());
    m_client = m_stack->Connect(Endpoint());
    ASSERT_FALSE(m_stack->TakeOutput(128).empty());

    const bool retransmitted = AdvanceUntilOutput(netstack::PacketPath::Peer);
    const bool delivered = Deliver() && Deliver() && Deliver();
    m_server = m_stack->TakeAccepted();

    EXPECT_TRUE(retransmitted);
    EXPECT_TRUE(delivered);
    EXPECT_EQ(m_client->State(), netstack::StreamState::Open);
    EXPECT_TRUE(m_server && m_server->State() == netstack::StreamState::Open);
}

TEST_P(Given_NetStack, When_SynAckIsLost_Then_DeadlineRetransmissionConnects)
{
    m_stack->Listen(Endpoint());
    m_client = m_stack->Connect(Endpoint());
    ASSERT_TRUE(Deliver());
    ASSERT_FALSE(m_stack->TakeOutput(128).empty());

    const bool retransmitted = AdvanceUntilOutput(netstack::PacketPath::Host);
    const bool delivered = Deliver() && Deliver() && Deliver();
    m_server = m_stack->TakeAccepted();

    EXPECT_TRUE(retransmitted);
    EXPECT_TRUE(delivered);
    EXPECT_EQ(m_client->State(), netstack::StreamState::Open);
    EXPECT_TRUE(m_server && m_server->State() == netstack::StreamState::Open);
}

TEST_P(Given_NetStack, When_FinalHandshakeAckIsLost_Then_DuplicateSynAckRecovers)
{
    m_stack->Listen(Endpoint());
    m_client = m_stack->Connect(Endpoint());
    ASSERT_TRUE(Deliver());
    ASSERT_TRUE(Deliver());
    ASSERT_FALSE(m_stack->TakeOutput(128).empty());
    ASSERT_EQ(m_stack->TakeAccepted(), nullptr);

    const bool retransmitted = AdvanceUntilOutput(netstack::PacketPath::Host);
    const bool delivered = Deliver() && Deliver();
    m_server = m_stack->TakeAccepted();

    EXPECT_TRUE(retransmitted);
    EXPECT_TRUE(delivered);
    EXPECT_EQ(m_client->State(), netstack::StreamState::Open);
    EXPECT_TRUE(m_server && m_server->State() == netstack::StreamState::Open);
}

TEST_P(Given_NetStack, When_PeerNeverResponds_Then_TimeoutFailsStreamAndReleasesPort)
{
    m_stack->Listen(Endpoint());
    m_client = m_stack->Connect(Endpoint());
    auto& reservations = m_injector.create<fakes::FakeTcpPortReservationFactory&>();
    ASSERT_EQ(*reservations.Active, 1U);
    constexpr std::size_t MaximumTimeoutEvents = 4096;
    std::size_t transmissions = m_stack->TakeOutput(128).size();

    for (std::size_t event = 0;
         event < MaximumTimeoutEvents && m_client->State() == netstack::StreamState::Connecting;
         ++event)
    {
        if (!AdvanceDeadline())
        {
            break;
        }
        transmissions += m_stack->TakeOutput(128).size();
    }
    auto replacement = m_stack->Connect(Endpoint());
    const bool connected = Deliver() && Deliver() && Deliver();
    m_server = m_stack->TakeAccepted();

    EXPECT_EQ(m_client->State(), netstack::StreamState::Failed);
    EXPECT_GT(transmissions, 1U);
    EXPECT_EQ(*reservations.Active, 1U);
    EXPECT_TRUE(connected);
    EXPECT_EQ(replacement->State(), netstack::StreamState::Open);
    EXPECT_TRUE(m_server && m_server->State() == netstack::StreamState::Open);
}

TEST_P(Given_NetStack, When_DataSegmentIsLost_Then_DeadlineRetransmissionDeliversIt)
{
    ASSERT_NO_FATAL_FAILURE(Establish(UseIpv6()));
    const std::vector<std::uint8_t> m_bytes{1, 2, 3, 4};
    ASSERT_EQ(m_client->TryWriteSome(m_bytes.data(), m_bytes.size()), m_bytes.size());
    ASSERT_FALSE(m_stack->TakeOutput(128).empty());

    const bool retransmitted = AdvanceUntilOutput(netstack::PacketPath::Peer);
    const bool delivered = Deliver();
    const auto m_received = m_server->TryReadSome(m_bytes.size());
    const auto extra = m_server->TryReadSome(1);

    EXPECT_TRUE(retransmitted);
    EXPECT_TRUE(delivered);
    EXPECT_EQ(m_received, m_bytes);
    EXPECT_FALSE(extra.has_value());
}

TEST_P(Given_NetStack, When_DataAckIsLost_Then_RetransmissionDoesNotDuplicateApplicationBytes)
{
    ASSERT_NO_FATAL_FAILURE(Establish(UseIpv6()));
    const std::vector<std::uint8_t> m_bytes{1, 2, 3, 4};
    ASSERT_EQ(m_client->TryWriteSome(m_bytes.data(), m_bytes.size()), m_bytes.size());
    ASSERT_TRUE(Deliver());
    ASSERT_EQ(m_server->TryReadSome(m_bytes.size()), m_bytes);
    ASSERT_TRUE(AdvanceUntilOutput(netstack::PacketPath::Host));
    ASSERT_FALSE(m_stack->TakeOutput(128).empty());

    const bool retransmitted = AdvanceUntilOutput(netstack::PacketPath::Peer);
    const bool delivered = Deliver();
    const auto duplicate = m_server->TryReadSome(1);
    const bool acknowledged = AdvanceUntilOutput(netstack::PacketPath::Host);

    EXPECT_TRUE(retransmitted);
    EXPECT_TRUE(delivered);
    EXPECT_FALSE(duplicate.has_value());
    EXPECT_TRUE(acknowledged);
}

TEST_P(Given_NetStack, When_FinIsLost_Then_DeadlineRetransmissionDeliversEof)
{
    ASSERT_NO_FATAL_FAILURE(Establish(UseIpv6()));
    ASSERT_TRUE(m_client->TryShutdownWrite());
    ASSERT_FALSE(m_stack->TakeOutput(128).empty());

    const bool retransmitted = AdvanceUntilOutput(netstack::PacketPath::Peer);
    const bool delivered = Deliver();
    const auto eof = m_server->TryReadSome(1);

    EXPECT_TRUE(retransmitted);
    EXPECT_TRUE(delivered);
    EXPECT_EQ(eof, std::vector<std::uint8_t>{});
}

TEST_P(Given_NetStack, When_BothSidesClose_Then_TimeWaitEventuallyReleasesReservedPort)
{
    ASSERT_NO_FATAL_FAILURE(Establish(UseIpv6()));
    auto& reservations = m_injector.create<fakes::FakeTcpPortReservationFactory&>();
    ASSERT_TRUE(m_client->TryShutdownWrite());
    ASSERT_TRUE(Deliver());
    ASSERT_TRUE(m_server->TryShutdownWrite());
    ASSERT_TRUE(Deliver());
    ASSERT_TRUE(Deliver());
    ASSERT_EQ(*reservations.Active, 1U);
    constexpr std::size_t MaximumCloseEvents = 4096;

    for (std::size_t event = 0; event < MaximumCloseEvents && *reservations.Active != 0; ++event)
    {
        if (!AdvanceDeadline())
        {
            break;
        }
    }
    const auto state = m_client->State();

    EXPECT_EQ(*reservations.Active, 0U);
    EXPECT_EQ(state, netstack::StreamState::Closed);
    EXPECT_FALSE(m_stack->NextDeadline().has_value());
}

TEST_P(Given_NetStack,
       When_ClientReusesPortAfterTimeWaitExpires_Then_FreshConnectionCanBeEstablished)
{
    auto& reservations = m_injector.create<fakes::FakeTcpPortReservationFactory&>();
    const auto originalPort = reservations.NextPort;
    ASSERT_NO_FATAL_FAILURE(Establish(UseIpv6()));
    ASSERT_TRUE(m_server->TryShutdownWrite());
    ASSERT_TRUE(Deliver());
    ASSERT_EQ(m_client->TryReadSome(1), std::vector<std::uint8_t>{});
    ASSERT_TRUE(m_client->TryShutdownWrite());
    ASSERT_TRUE(Deliver());
    ASSERT_TRUE(Deliver());
    ASSERT_TRUE(m_client->TryClose());
    ASSERT_TRUE(m_server->TryClose());
    ASSERT_EQ(*reservations.Active, 0U);
    // Early TIME_WAIT reopening is optional, not a baseline TCP acceptance condition.
    // Advance actual timer events beyond the retained tuple's lifetime before reuse.
    constexpr unsigned TimeWaitExpiryEvents = 1024;
    for (unsigned event = 0; event < TimeWaitExpiryEvents && m_stack->NextDeadline(); ++event)
    {
        ASSERT_TRUE(AdvanceDeadline());
    }
    ASSERT_FALSE(m_stack->NextDeadline());
    reservations.NextPort = originalPort;

    m_client = m_stack->Connect(Endpoint());
    const bool deliveredSyn = Deliver();
    const bool deliveredReply = Deliver();
    const bool deliveredAcknowledgement = Deliver();
    auto accepted = m_stack->TakeAccepted();

    EXPECT_TRUE(deliveredSyn);
    EXPECT_TRUE(deliveredReply);
    EXPECT_TRUE(deliveredAcknowledgement);
    EXPECT_EQ(m_client->State(), netstack::StreamState::Open);
    EXPECT_NE(accepted, nullptr);
}

TEST_P(Given_NetStack, When_ReceiveWindowCloses_Then_ReadingResumesFullTransfer)
{
    ASSERT_NO_FATAL_FAILURE(Establish(UseIpv6()));
    ASSERT_TRUE(FillReceiveWindow());

    const bool completed = CompleteTransfer();
    const auto extra = m_server->TryReadSome(1);

    EXPECT_TRUE(m_zeroWindow);
    EXPECT_TRUE(m_writeBlocked);
    EXPECT_TRUE(completed);
    EXPECT_EQ(m_received, m_bytes);
    EXPECT_FALSE(extra.has_value());
}

TEST_P(Given_NetStack, When_WindowReopeningUpdatesAreLost_Then_PersistProbeRecoversTransfer)
{
    ASSERT_NO_FATAL_FAILURE(Establish(UseIpv6()));
    ASSERT_TRUE(FillReceiveWindow());

    const bool drained = DrainServer();
    const bool delivered = DeliverObserved(true);
    const bool completed = CompleteTransfer();

    EXPECT_TRUE(drained);
    EXPECT_TRUE(delivered);
    EXPECT_GT(m_droppedUpdates, 0U);
    EXPECT_TRUE(m_persistProbe);
    EXPECT_TRUE(completed);
    EXPECT_EQ(m_received, m_bytes);
}

TEST_P(Given_NetStack, When_PeerFragmentsArriveOutOfOrder_Then_CoreStreamReceivesReassembledBytes)
{
    ASSERT_NO_FATAL_FAILURE(Prepare(true));

    const auto delivered = DeliverFragments(netstack::PacketPath::Peer);
    const auto m_received = m_client->TryReadSome(payload.size());

    EXPECT_TRUE(delivered);
    EXPECT_EQ(m_received, payload);
    EXPECT_FALSE(m_stack->HasOutput(netstack::PacketPath::Host));
}

TEST_P(Given_NetStack,
       When_HostFragmentsArriveOutOfOrder_Then_ServiceStreamReceivesReassembledBytes)
{
    ASSERT_NO_FATAL_FAILURE(Prepare(false));

    const auto delivered = DeliverFragments(netstack::PacketPath::Host);
    const auto m_received = m_server->TryReadSome(payload.size());

    EXPECT_TRUE(delivered);
    EXPECT_EQ(m_received, payload);
    EXPECT_FALSE(m_stack->HasOutput(netstack::PacketPath::HostNetwork));
}

TEST_P(Given_NetStack,
       When_UnownedPeerFragmentsArrive_Then_ReassembledPacketReturnsToHostWithoutReset)
{
    ASSERT_NO_FATAL_FAILURE(Prepare(true));
    m_client->Abort();
    (void)m_stack->TakeOutput(128);
    const auto originalEnvelope = net::packet::ParseIpEnvelope(original);
    ASSERT_TRUE(originalEnvelope.has_value());
    const std::vector<std::uint8_t> expected(original.begin() + originalEnvelope->PayloadOffset,
                                             original.end());

    const auto delivered = DeliverFragments(netstack::PacketPath::Peer);
    const auto output = m_stack->TakeOutput(128);
    const auto envelope =
        output.size() == 1 ? net::packet::ParseIpEnvelope(output.front().Bytes) : std::nullopt;
    std::vector<std::uint8_t> actual;
    if (envelope)
    {
        actual.assign(output.front().Bytes.begin() + envelope->PayloadOffset,
                      output.front().Bytes.end());
    }
    ASSERT_EQ(output.size(), 1U);
    ASSERT_TRUE(envelope);

    EXPECT_TRUE(delivered);
    EXPECT_EQ(output.size(), 1U);
    EXPECT_EQ(output.front().Path, netstack::PacketPath::Host);
    EXPECT_EQ(actual, expected);
    EXPECT_FALSE(envelope->Fragmented);
}

TEST_P(Given_NetStack, When_StackRestartsBetweenFragments_Then_OldDatagramCannotComplete)
{
    ASSERT_NO_FATAL_FAILURE(Prepare(true));
    ASSERT_TRUE(m_stack->Input(netstack::PacketPath::Peer, fragments.front()));
    m_stack->Stop();
    m_stack->Start(m_configuration);
    bool delivered = true;

    for (std::size_t index = 1; index < fragments.size(); ++index)
    {
        delivered = m_stack->Input(netstack::PacketPath::Peer, fragments[index]) && delivered;
    }
    const auto output = m_stack->TakeOutput(128);

    EXPECT_TRUE(delivered);
    EXPECT_TRUE(output.empty());
}

TEST_P(Given_NetStack, When_PeerAssignmentsChangeBetweenFragments_Then_OldDatagramCannotComplete)
{
    ASSERT_NO_FATAL_FAILURE(Prepare(true));
    ASSERT_TRUE(m_stack->Input(netstack::PacketPath::Peer, fragments.front()));
    bool delivered = true;

    m_stack->InvalidatePeerPackets();
    for (std::size_t index = 1; index < fragments.size(); ++index)
    {
        delivered = m_stack->Input(netstack::PacketPath::Peer, fragments[index]) && delivered;
    }
    const auto output = m_stack->TakeOutput(128);

    EXPECT_TRUE(delivered);
    EXPECT_TRUE(output.empty());
    EXPECT_EQ(m_client->State(), netstack::StreamState::Open);
    EXPECT_EQ(m_server->State(), netstack::StreamState::Open);
}

TEST_F(Given_NetStack, When_HostFragmentsConcealUdp_Then_DatagramReturnsToOutboundPath)
{
    const auto original = fakes::Ipv6UdpWithDestinationOptions(*m_configuration.Node.Ipv6,
                                                               *m_configuration.Service.Ipv6);
    const auto fragments = fakes::FragmentIpv6(original);
    bool delivered = true;

    for (const auto& fragment : fragments)
    {
        delivered = m_stack->Input(netstack::PacketPath::Host, fragment) && delivered;
    }
    const auto output = m_stack->TakeOutput(128);
    ASSERT_EQ(output.size(), 1U);

    EXPECT_TRUE(delivered);
    EXPECT_EQ(output.size(), 1U);
    EXPECT_EQ(output.front().Path, netstack::PacketPath::HostNetwork);
    EXPECT_EQ(output.front().Bytes, original);
}

TEST_F(Given_NetStack, When_PeerFragmentsConcealUdp_Then_DatagramReturnsToHost)
{
    const auto original = fakes::Ipv6UdpWithDestinationOptions(*m_configuration.Service.Ipv6,
                                                               *m_configuration.Node.Ipv6);
    const auto fragments = fakes::FragmentIpv6(original);
    bool delivered = true;

    for (const auto& fragment : fragments)
    {
        delivered = m_stack->Input(netstack::PacketPath::Peer, fragment) && delivered;
    }
    const auto output = m_stack->TakeOutput(128);
    ASSERT_EQ(output.size(), 1U);

    EXPECT_TRUE(delivered);
    EXPECT_EQ(output.size(), 1U);
    EXPECT_EQ(output.front().Path, netstack::PacketPath::Host);
    EXPECT_EQ(output.front().Bytes, original);
}

TEST_F(Given_NetStack, When_PeerAssignmentsChange_Then_QueuedPlaintextIsDiscardedWithoutClosingTcp)
{
    ASSERT_NO_FATAL_FAILURE(Establish(true));
    const std::uint8_t byte = 42;
    ASSERT_EQ(m_client->TryWriteSome(&byte, 1), 1U);
    ASSERT_TRUE(m_stack->HasOutput(netstack::PacketPath::Peer));

    m_stack->InvalidatePeerPackets();

    EXPECT_FALSE(m_stack->HasOutput(netstack::PacketPath::Peer));
    EXPECT_EQ(m_client->State(), netstack::StreamState::Open);
    EXPECT_EQ(m_server->State(), netstack::StreamState::Open);
}

INSTANTIATE_TEST_SUITE_P(AddressFamilies,
                         Given_NetStack,
                         testing::Values(FragmentMode::Ipv4,
                                         FragmentMode::Ipv6,
                                         FragmentMode::Ipv6DestinationOptions));

} // namespace tailgate::tests
