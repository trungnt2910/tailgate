#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <tailgate/control/client/Connection.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/derp/Client.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/serve/FunnelConfig.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Connection.h>

#include "HostedConnectionRegistry.h"
#include "State.h"
#include "event/EventRegistry.h"

namespace tailgate::linux_frontend
{

void RunTunnel(
    const tailgate::crypto::Bytes32& nodePrivateKey,
    const tailgate::crypto::Bytes32& nodePublicKey,
    const tailgate::crypto::Bytes32& discoPrivateKey,
    const std::string& selfIp,
    const std::string& selfIpv6,
    const std::string& selfDnsName,
    const std::string& domain,
    const std::string& initialDnsResolver,
    const std::vector<std::string>& initialDnsDomains,
    const std::vector<std::string>& initialDnsDefaultResolvers,
    const std::vector<tailgate::types::netmap::NetworkConfig::DnsRoute>& initialDnsRoutes,
    const std::vector<tailgate::types::netmap::PeerConfig>& peerConfigs,
    int derpRegion,
    const std::string& derpHost,
    const std::string& exitNode,
    bool acceptDns,
    const tailgate::serve::FunnelConfig& funnel,
    const std::string& funnelCertificatePem,
    const std::string& funnelPrivateKeyPem,
    std::unique_ptr<tailgate::control::client::Connection> controlConnection,
    event::EventRegistry& eventRegistry,
    tailgate::wgengine::Engine& engine,
    tailgate::wgengine::Session& session,
    tailgate::wgengine::magicsock::Connection& connection,
    tailgate::derp::ConnectionFactory& derpConnectionFactory,
    HostedConnectionRegistry& hostedConnections,
    DaemonStatus& status,
    int& readyFd,
    bool configureHost = true,
    bool persistStatus = true,
    bool encryptedPacketTransport = false,
    int relayControlFd = -1,
    std::function<void(const tailgate::types::netmap::NetworkConfig&)> networkMapUpdated = {},
    tailgate::derp::DerpClient::Authenticator derpAuthenticator = {});

} // namespace tailgate::linux_frontend
