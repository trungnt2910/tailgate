#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <tailgate/base/ByteStream.h>
#include <tailgate/control/base/Noise.h>
#include <tailgate/crypto/Crypto.h>

namespace tailgate::control::base
{

struct ControlHandshakeResult
{
    NoiseKeys Keys;
    std::vector<std::uint8_t> ProactiveFrames;
};

class ControlHandshake
{
public:
    static constexpr const char* DefaultHost = "controlplane.tailscale.com";
    // ts2021 is served on both ports. The Noise handshake authenticates the server with its
    // pinned key, so the plaintext service is first choice and TLS is a middlebox fallback.
    static constexpr const char* PlaintextService = "80";
    static constexpr const char* TlsService = "443";

    ControlHandshake(tailgate::crypto::Bytes32 machinePrivateKey,
                     tailgate::crypto::Bytes32 ephemeralPrivateKey);

    [[nodiscard]] ControlHandshakeResult Run(tailgate::base::IByteStream& stream,
                                             const std::string& host);

private:
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildUpgradeRequest(const std::string& host, const std::vector<std::uint8_t>& message1);
    [[nodiscard]] static std::size_t FindHeaderEnd(const std::vector<std::uint8_t>& data);

    NoiseInitiator m_noise;
};

} // namespace tailgate::control::base
