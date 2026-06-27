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

    ControlHandshake(Bytes32 machinePrivateKey, Bytes32 ephemeralPrivateKey);

    [[nodiscard]] ControlHandshakeResult Run(IByteStream& stream, const std::string& host);

private:
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildUpgradeRequest(const std::string& host, const std::vector<std::uint8_t>& message1);
    [[nodiscard]] static std::size_t FindHeaderEnd(const std::vector<std::uint8_t>& data);

    NoiseInitiator m_noise;
};

} // namespace tailgate::protocol
