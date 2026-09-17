#pragma once

#include <map>
#include <string>

#include <tailgate/drive/FileSystemForLocal.h>
#include <tailgate/ipn/ipnlocal/LocalServices.h>
#include <tailgate/wgengine/netstack/Stack.h>

namespace tailgate::ipn::ipnlocal::impl
{

class LocalServicesImpl final : public LocalServices
{
public:
    LocalServicesImpl(std::shared_ptr<wgengine::netstack::Stack> stack,
                      std::shared_ptr<drive::FileSystemForLocal> drive,
                      std::shared_ptr<base::TimeProvider> timeProvider);
    ~LocalServicesImpl() override;
    void SetNetworkConfig(const types::netmap::NetworkConfig& config) override;
    void Stop() noexcept override;
    [[nodiscard]] bool HandleHostPacket(std::span<const std::uint8_t> packet) override;
    [[nodiscard]] bool HandlePeerPacket(const crypto::Bytes32& authenticatedPeer,
                                        std::span<const std::uint8_t> packet) override;
    void Poll() override;
    [[nodiscard]] std::vector<ServicePacket> TakeOutput(std::size_t maximumPackets) override;
    [[nodiscard]] std::optional<base::TimeProvider::TimePoint> NextDeadline() const override;

private:
    [[nodiscard]] bool IsService(const net::IpAddress& address) const;
    [[nodiscard]] bool IsSelf(const net::IpAddress& address) const;
    void UpdatePeers(const types::netmap::NetworkConfig& config);

    std::shared_ptr<wgengine::netstack::Stack> m_ownedStack;
    std::shared_ptr<drive::FileSystemForLocal> m_ownedDrive;
    std::shared_ptr<base::TimeProvider> m_ownedTimeProvider;
    wgengine::netstack::Stack& m_stack;
    drive::FileSystemForLocal& m_drive;
    base::TimeProvider& m_timeProvider;
    wgengine::netstack::Configuration m_configuration;
    std::string m_selfKey;
    std::map<std::string, crypto::Bytes32> m_peersByAddress;
    bool m_started = false;
    bool m_moreWork = false;
};

} // namespace tailgate::ipn::ipnlocal::impl
