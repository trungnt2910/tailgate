#include "ServerSessionImpl.h"

#include <string_view>
#include <utility>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::hosted::impl
{

namespace
{

constexpr std::string_view RejectionReason =
    "node authentication or tailnet visibility check failed";
constexpr std::string_view NodeKeyPrefix = "nodekey:";

} // namespace

ServerSessionImpl::ServerSessionImpl(tailgate::hosted::ServerSessionOptions options,
                                     tailgate::base::TimeProvider& timeProvider)
    : m_timeProvider(timeProvider), m_options(std::move(options))
{
}

tailgate::hosted::Frame ServerSessionImpl::StartAuthentication()
{
    std::lock_guard lock(m_mutex);
    RequireState(State::Created);
    m_serverNonce = tailgate::crypto::GeneratePrivateKey();
    m_state = State::ChallengeSent;
    return tailgate::hosted::Frame(
        tailgate::hosted::MessageType::ServerChallenge,
        tailgate::hosted::ProtocolCodec::EncodeChallenge(
            tailgate::hosted::Challenge(m_options.RelayPublicKey, m_serverNonce)));
}

tailgate::hosted::ServerAuthenticationResult
ServerSessionImpl::EvaluateAuthentication(const tailgate::hosted::Frame& frame)
{
    std::lock_guard lock(m_mutex);
    RequireState(State::ChallengeSent);
    if (frame.Type() != tailgate::hosted::MessageType::Authenticate)
    {
        throw tailgate::hosted::ServerSessionException(
            tailgate::hosted::ServerSessionError::UnexpectedFrame);
    }
    m_authentication = tailgate::hosted::ProtocolCodec::DecodeAuthentication(frame.Payload());
    const tailgate::crypto::Bytes32 expectedProof =
        tailgate::hosted::CreateClientProof(m_options.RelayPrivateKey,
                                            m_authentication->NodePublicKey(),
                                            m_serverNonce,
                                            m_authentication->ClientNonce());
    m_proofValid = tailgate::hosted::ProofMatches(expectedProof, m_authentication->ClientProof());
    m_tailnetMatches = m_authentication->Tailnet() == m_options.ExpectedTailnet;
    m_state = State::AuthenticationEvaluated;
    return tailgate::hosted::ServerAuthenticationResult{
        .Identity = *m_authentication,
        .ProofValid = m_proofValid,
        .TailnetMatches = m_tailnetMatches,
    };
}

tailgate::hosted::Frame ServerSessionImpl::CompleteAuthentication(bool nodeVisible)
{
    std::lock_guard lock(m_mutex);
    RequireState(State::AuthenticationEvaluated);
    if (!m_proofValid || !m_tailnetMatches || !nodeVisible)
    {
        m_state = State::Rejected;
        return tailgate::hosted::Frame(
            tailgate::hosted::MessageType::Rejected,
            tailgate::hosted::ProtocolCodec::EncodeRejection(
                tailgate::hosted::Rejection(std::string(RejectionReason))));
    }
    m_state = State::Authenticated;
    return tailgate::hosted::Frame(
        tailgate::hosted::MessageType::Authenticated,
        tailgate::hosted::ProtocolCodec::EncodeSession(tailgate::hosted::Session(
            m_authentication->Tailnet(),
            m_options.RelayHostName,
            m_options.RelayHostAddress,
            tailgate::hosted::CreateServerProof(m_options.RelayPrivateKey,
                                                m_authentication->NodePublicKey(),
                                                m_serverNonce,
                                                m_authentication->ClientNonce()))));
}

tailgate::types::netmap::NetworkConfig
ServerSessionImpl::AcceptInitialNetworkMap(const tailgate::hosted::Frame& frame)
{
    std::lock_guard lock(m_mutex);
    RequireState(State::Authenticated);
    if (frame.Type() != tailgate::hosted::MessageType::NetworkMap)
    {
        throw tailgate::hosted::ServerSessionException(
            tailgate::hosted::ServerSessionError::UnexpectedFrame);
    }
    tailgate::types::netmap::NetworkConfig config =
        tailgate::hosted::ProtocolCodec::DecodeNetworkConfig(frame.Payload());
    if (!ValidateNetworkMap(config))
    {
        throw tailgate::hosted::ServerSessionException(
            tailgate::hosted::ServerSessionError::NetworkMapIdentityChanged);
    }
    m_networkMap = config;
    m_state = State::Active;
    return config;
}

tailgate::hosted::ServerSessionProcessResult
ServerSessionImpl::Process(const tailgate::hosted::Frame& frame)
{
    std::lock_guard lock(m_mutex);
    RequireActive();
    tailgate::hosted::ServerSessionProcessResult result;
    if (frame.Type() == tailgate::hosted::MessageType::ClientPacket)
    {
        result.PeerPacketPayload = frame.Payload();
    }
    else if (frame.Type() == tailgate::hosted::MessageType::PeerEndpoint)
    {
        result.VerifiedPeerEndpoint =
            tailgate::hosted::ProtocolCodec::DecodePeerEndpoint(frame.Payload());
    }
    else if (frame.Type() == tailgate::hosted::MessageType::NetworkMap)
    {
        tailgate::types::netmap::NetworkConfig next =
            tailgate::hosted::ProtocolCodec::DecodeNetworkConfig(frame.Payload());
        if (!ValidateNetworkMap(next))
        {
            throw tailgate::hosted::ServerSessionException(
                tailgate::hosted::ServerSessionError::NetworkMapIdentityChanged);
        }
        m_networkMap = next;
        result.NetworkMap = std::move(next);
    }
    else if (frame.Type() == tailgate::hosted::MessageType::TailnetDnsQuery)
    {
        const std::optional<tailgate::net::Ipv4Address> expectedSource =
            tailgate::net::Ipv4Address::TryParse(m_networkMap.SelfAddress());
        const std::optional<tailgate::net::packet::Ipv4UdpDatagram> query =
            tailgate::net::packet::Ipv4UdpDatagram::Parse(frame.Payload());
        if (!expectedSource || !query || query->Source() != expectedSource->HostOrder())
        {
            throw tailgate::hosted::ServerSessionException(
                tailgate::hosted::ServerSessionError::InvalidTailnetDnsQuery);
        }
        std::optional<std::vector<std::uint8_t>> response =
            tailgate::net::dns::TailnetDnsResponse::Build(m_networkMap, frame.Payload());
        if (!response)
        {
            throw tailgate::hosted::ServerSessionException(
                tailgate::hosted::ServerSessionError::InvalidTailnetDnsQuery);
        }
        result.DnsName = tailgate::net::dns::DnsQuery::Name(query->Payload());
        result.RemoteOutput.emplace_back(tailgate::hosted::MessageType::TailnetDnsResponse,
                                         std::move(*response));
    }
    else if (frame.Type() == tailgate::hosted::MessageType::DerpResponse)
    {
        result.DerpResponse = tailgate::hosted::ProtocolCodec::DecodeDerpResponse(frame.Payload());
    }
    else if (frame.Type() == tailgate::hosted::MessageType::Heartbeat)
    {
        result.ClientReady = true;
    }
    else if (frame.Type() == tailgate::hosted::MessageType::PumpSchedule)
    {
        const auto schedule = tailgate::hosted::TryDecodePumpSchedule(frame.Payload());
        if (!schedule)
        {
            throw tailgate::hosted::PumpException(tailgate::hosted::PumpError::InvalidMessage);
        }
        result.PumpScheduleChanged = AcceptPump(*schedule);
    }
    else if (frame.Type() == tailgate::hosted::MessageType::Shutdown)
    {
        result.Shutdown = true;
    }
    return result;
}

tailgate::hosted::ServerDerpChallenge
ServerSessionImpl::BuildDerpChallenge(const tailgate::crypto::Bytes32& serverKey)
{
    std::lock_guard lock(m_mutex);
    RequireActive();
    const std::uint64_t requestId = m_nextDerpRequestId++;
    return tailgate::hosted::ServerDerpChallenge{
        .RequestId = requestId,
        .Output = tailgate::hosted::Frame(
            tailgate::hosted::MessageType::DerpChallenge,
            tailgate::hosted::ProtocolCodec::EncodeDerpChallenge(
                tailgate::hosted::DerpAuthenticationChallenge(requestId, serverKey))),
    };
}

tailgate::hosted::Frame ServerSessionImpl::BuildHeartbeat() const
{
    std::lock_guard lock(m_mutex);
    RequireActive();
    return tailgate::hosted::Frame(tailgate::hosted::MessageType::Heartbeat, {});
}

tailgate::hosted::Frame
ServerSessionImpl::BuildServerPacket(std::vector<std::uint8_t> peerPacketPayload) const
{
    std::lock_guard lock(m_mutex);
    RequireActive();
    return tailgate::hosted::Frame(tailgate::hosted::MessageType::ServerPacket,
                                   std::move(peerPacketPayload));
}

void ServerSessionImpl::RequireState(State expected) const
{
    if (m_state != expected)
    {
        throw tailgate::hosted::ServerSessionException(
            tailgate::hosted::ServerSessionError::InvalidState);
    }
}

void ServerSessionImpl::RequireActive() const
{
    RequireState(State::Active);
}

bool ServerSessionImpl::ValidateNetworkMap(
    const tailgate::types::netmap::NetworkConfig& candidate) const
{
    const std::string expectedNodeKey =
        std::string(NodeKeyPrefix) +
        tailgate::crypto::BytesToHex(m_authentication->NodePublicKey().data(),
                                     m_authentication->NodePublicKey().size());
    return candidate.Domain() == m_authentication->Tailnet() &&
           candidate.SelfNodeId() == m_authentication->NodeId() &&
           candidate.SelfKey() == expectedNodeKey;
}

ServerSessionFactoryImpl::ServerSessionFactoryImpl(
    tailgate::base::TimeProvider& timeProvider) noexcept
    : m_timeProvider(timeProvider)
{
}

std::unique_ptr<tailgate::hosted::ServerSession>
ServerSessionFactoryImpl::CreateServerSession(tailgate::hosted::ServerSessionOptions options)
{
    return std::make_unique<ServerSessionImpl>(std::move(options), m_timeProvider);
}

bool ServerSessionImpl::AcceptPump(const tailgate::hosted::PumpSchedule& schedule)
{
    // Process already holds the session lock. Old schedules must not undo a newer cancellation.
    if (schedule.RequestId <= m_pumpRequestId)
    {
        return false;
    }
    m_pumpRequestId = schedule.RequestId;
    m_pumpDeadline =
        schedule.Delay ? std::optional(m_timeProvider.Now() + *schedule.Delay) : std::nullopt;
    if (m_pumpDeadline && m_lastPump && *m_pumpDeadline < *m_lastPump + MinimumPumpInterval)
    {
        m_pumpDeadline = *m_lastPump + MinimumPumpInterval;
    }
    return true;
}

std::optional<tailgate::base::TimeProvider::TimePoint> ServerSessionImpl::NextPumpDeadline() const
{
    std::lock_guard lock(m_mutex);
    RequireActive();
    return m_pumpDeadline;
}

std::optional<tailgate::hosted::Frame> ServerSessionImpl::TakeDuePump()
{
    std::lock_guard lock(m_mutex);
    RequireActive();
    if (!m_pumpDeadline || m_timeProvider.Now() < *m_pumpDeadline)
    {
        return std::nullopt;
    }
    m_pumpDeadline.reset();
    m_lastPump = m_timeProvider.Now();
    return tailgate::hosted::EncodePumpReply(m_pumpRequestId);
}

} // namespace tailgate::hosted::impl
