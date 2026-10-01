#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/wireguard/Router.h>

namespace tailgate::wgengine
{

struct PeerIdentity
{
    crypto::Bytes32 NodePrivateKey{};
    crypto::Bytes32 NodePublicKey{};
    crypto::Bytes32 DiscoPrivateKey{};

    [[nodiscard]] bool operator==(const PeerIdentity&) const = default;
};

enum class PeerProtocolError
{
    IdentityChanged,
    NotInitialized,
};

class PeerProtocolException final : public std::logic_error
{
public:
    explicit PeerProtocolException(PeerProtocolError error);
    [[nodiscard]] PeerProtocolError Error() const noexcept;

private:
    PeerProtocolError m_error;
};

// One identity's cryptographic state, shared by native and hosted packet paths.
// Path shutdown never resets it. Reset explicitly before changing identity.
// All access belongs to the node runtime's serialized execution context.
class PeerProtocol final
{
public:
    // All packet paths and workers must be retired first.
    void Reset() noexcept;
    void Initialize(PeerIdentity identity,
                    const std::vector<types::netmap::PeerConfig>& peers,
                    const std::string& exitNode);
    [[nodiscard]] bool Initialized() const noexcept;
    [[nodiscard]] wireguard::WireGuardRouter& Router();
    [[nodiscard]] disco::Disco& Disco();

private:
    PeerIdentity m_identity;
    std::unique_ptr<wireguard::WireGuardRouter> m_router;
    std::unique_ptr<disco::Disco> m_disco;
};

} // namespace tailgate::wgengine
