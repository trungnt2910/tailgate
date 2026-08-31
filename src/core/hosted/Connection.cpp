#include "tailgate/hosted/Connection.h"

#include <array>
#include <format>
#include <string_view>
#include <utility>

namespace tailgate::hosted
{
namespace
{

constexpr std::array<std::string_view, 4> ErrorMessages{
    "Tailgate server did not provide an identity challenge.",
    "Tailgate server rejected authentication.",
    "Tailgate server returned an invalid authentication response.",
    "Tailgate server identity proof is invalid.",
};

const char* ErrorMessage(ConnectionError error)
{
    return ErrorMessages[static_cast<std::size_t>(error)].data();
}

std::string ExceptionMessage(ConnectionError error, const std::string& reason)
{
    return reason.empty() ? std::string(ErrorMessage(error))
                          : std::format("{} {}", ErrorMessage(error), reason);
}

} // namespace

ConnectionException::ConnectionException(ConnectionError error, std::string reason)
    : std::runtime_error(ExceptionMessage(error, reason)),
      m_error(error),
      m_reason(std::move(reason))
{
}

ConnectionError ConnectionException::Error() const noexcept
{
    return m_error;
}

const std::string& ConnectionException::Reason() const noexcept
{
    return m_reason;
}

Connection::Connection(tailgate::wgengine::tstun::Device& device,
                       tailgate::hosted::Client& client) noexcept
    : m_device(device), m_client(client)
{
}

ConnectionResult Connection::Connect(ConnectionOptions options)
{
    const bool nonBlockingAfterConnect = options.Socket.NonBlockingAfterConnect;
    options.Socket.NonBlockingAfterConnect = false;
    std::unique_ptr<tailgate::types::nettype::TcpSocket> stream =
        m_device.OpenTransportSocket(options.Socket);
    Decoder decoder;
    decoder.Feed(RequestHttpUpgrade(*stream, options.HttpHost));
    const Frame challengeFrame = decoder.Read(*stream);
    if (challengeFrame.Type() != MessageType::ServerChallenge)
    {
        throw ConnectionException(ConnectionError::ChallengeExpected);
    }
    const Challenge challenge = ProtocolCodec::DecodeChallenge(challengeFrame.Payload());
    const tailgate::crypto::Bytes32 clientNonce = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 clientProof = CreateClientProof(options.Client.NodePrivateKey,
                                                                    challenge.RelayPublicKey(),
                                                                    challenge.ServerNonce(),
                                                                    clientNonce);
    const Authentication authentication(options.Client.Network.Domain(),
                                        options.Client.Network.SelfNodeId(),
                                        options.Hostname,
                                        options.OperatingSystem,
                                        options.OperatingSystemVersion,
                                        options.Client.NodePublicKey,
                                        clientNonce,
                                        clientProof);
    Frame(MessageType::Authenticate, ProtocolCodec::EncodeAuthentication(authentication))
        .Write(*stream);
    const Frame response = decoder.Read(*stream);
    if (response.Type() == MessageType::Rejected)
    {
        throw ConnectionException(ConnectionError::Rejected,
                                  ProtocolCodec::DecodeRejection(response.Payload()).Reason());
    }
    if (response.Type() != MessageType::Authenticated)
    {
        throw ConnectionException(ConnectionError::AuthenticationExpected);
    }
    Session session = ProtocolCodec::DecodeSession(response.Payload());
    const tailgate::crypto::Bytes32 expectedProof = CreateServerProof(options.Client.NodePrivateKey,
                                                                      challenge.RelayPublicKey(),
                                                                      challenge.ServerNonce(),
                                                                      authentication.ClientNonce());
    if (session.Tailnet() != options.Client.Network.Domain() ||
        !ProofMatches(expectedProof, session.ServerProof()))
    {
        throw ConnectionException(ConnectionError::SessionIdentityInvalid);
    }
    stream->WriteAll(m_client.Start(std::move(options.Client)));
    if (nonBlockingAfterConnect)
    {
        stream->SetNonBlocking(true);
    }
    return ConnectionResult{
        .Stream = std::move(stream),
        .RelayPublicKey = challenge.RelayPublicKey(),
        .RelaySession = std::move(session),
        .FrameDecoder = std::move(decoder),
    };
}

} // namespace tailgate::hosted
