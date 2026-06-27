#pragma once

#include "tailgate/ByteStream.h"
#include "tailgate/control/NetworkMap.h"
#include "tailgate/protocol/ControlRequests.h"
#include "tailgate/protocol/Crypto.h"

#include <memory>
#include <optional>
#include <string>

namespace tailgate::control
{

class ControlClient
{
public:
    ControlClient(IByteStream& stream,
                  const protocol::Bytes32& machinePrivateKey,
                  const protocol::Bytes32& nodePrivateKey,
                  const protocol::HostInfo& host);
    ~ControlClient();
    ControlClient(ControlClient&&) noexcept;
    ControlClient& operator=(ControlClient&&) noexcept;
    ControlClient(const ControlClient&) = delete;
    ControlClient& operator=(const ControlClient&) = delete;

    [[nodiscard]] NetworkConfig RegisterAndGetNetworkMap(const std::string& authKey);
    void SetDiscoPrivateKey(const protocol::Bytes32& privateKey);
    void SetPreferredDerp(int region);
    [[nodiscard]] std::optional<NetworkConfig> PollNetworkMap();
    void Logout();
    [[nodiscard]] const protocol::Bytes32& NodePublicKey() const;
    [[nodiscard]] const protocol::Bytes32& DiscoPrivateKey() const;

private:
    class Impl;
    std::unique_ptr<Impl> Implementation;
};

} // namespace tailgate::control
