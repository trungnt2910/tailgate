#pragma once

#include "tailgate/ByteStream.h"
#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/Noise.h"

#include <cstdint>
#include <string>
#include <vector>

namespace tailgate::protocol
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

    ControlHandshake(Bytes32 machinePrivateKey, Bytes32 ephemeralPrivateKey);

    [[nodiscard]] ControlHandshakeResult Run(IByteStream& stream, const std::string& host);

private:
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildUpgradeRequest(const std::string& host, const std::vector<std::uint8_t>& message1);
    [[nodiscard]] static std::size_t FindHeaderEnd(const std::vector<std::uint8_t>& data);

    NoiseInitiator m_noise;
};

} // namespace tailgate::protocol
