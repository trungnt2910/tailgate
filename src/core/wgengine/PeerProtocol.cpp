#include "tailgate/wgengine/PeerProtocol.h"

#include <array>
#include <utility>

namespace tailgate::wgengine
{
namespace
{

constexpr std::array ErrorMessages{
    "The peer protocol identity cannot change while the node is alive.",
    "The peer protocol has not been initialized.",
};

} // namespace

PeerProtocolException::PeerProtocolException(PeerProtocolError error)
    : std::logic_error(ErrorMessages[static_cast<std::size_t>(error)]), m_error(error)
{
}

PeerProtocolError PeerProtocolException::Error() const noexcept
{
    return m_error;
}

void PeerProtocol::Reset() noexcept
{
    m_router.reset();
    m_disco.reset();
    m_identity = {};
}

void PeerProtocol::Initialize(PeerIdentity identity,
                              const std::vector<types::netmap::PeerConfig>& peers,
                              const std::string& exitNode)
{
    if (m_router)
    {
        if (identity != m_identity)
        {
            throw PeerProtocolException(PeerProtocolError::IdentityChanged);
        }
        m_router->UpdatePeers(peers, exitNode);
        return;
    }
    auto router =
        std::make_unique<wireguard::WireGuardRouter>(identity.NodePrivateKey, peers, exitNode);
    auto disco = std::make_unique<disco::Disco>(identity.DiscoPrivateKey, identity.NodePublicKey);
    m_identity = identity;
    m_router = std::move(router);
    m_disco = std::move(disco);
}

bool PeerProtocol::Initialized() const noexcept
{
    return m_router != nullptr;
}

wireguard::WireGuardRouter& PeerProtocol::Router()
{
    if (!m_router)
    {
        throw PeerProtocolException(PeerProtocolError::NotInitialized);
    }
    return *m_router;
}

disco::Disco& PeerProtocol::Disco()
{
    if (!m_disco)
    {
        throw PeerProtocolException(PeerProtocolError::NotInitialized);
    }
    return *m_disco;
}

} // namespace tailgate::wgengine
