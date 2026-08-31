#include "tailgate/hosted/ServerSession.h"

#include <string_view>

namespace tailgate::hosted
{
namespace
{

constexpr std::string_view InvalidStateMessage =
    "The hosted server session operation is invalid in its current state.";
constexpr std::string_view UnexpectedFrameMessage =
    "The hosted client sent an unexpected protocol frame.";
constexpr std::string_view NetworkMapIdentityChangedMessage =
    "The hosted client network map does not match its authenticated identity.";
constexpr std::string_view InvalidTailnetDnsQueryMessage =
    "The hosted client Tailnet DNS query is invalid.";

const char* ErrorMessage(ServerSessionError error) noexcept
{
    switch (error)
    {
    case ServerSessionError::InvalidState:
        return InvalidStateMessage.data();
    case ServerSessionError::UnexpectedFrame:
        return UnexpectedFrameMessage.data();
    case ServerSessionError::NetworkMapIdentityChanged:
        return NetworkMapIdentityChangedMessage.data();
    case ServerSessionError::InvalidTailnetDnsQuery:
        return InvalidTailnetDnsQueryMessage.data();
    }
    return InvalidStateMessage.data();
}

} // namespace

ServerSessionException::ServerSessionException(ServerSessionError error)
    : std::runtime_error(ErrorMessage(error)), m_error(error)
{
}

ServerSessionError ServerSessionException::Error() const noexcept
{
    return m_error;
}

ServerSession::~ServerSession() = default;
ServerSessionFactory::~ServerSessionFactory() = default;

} // namespace tailgate::hosted
