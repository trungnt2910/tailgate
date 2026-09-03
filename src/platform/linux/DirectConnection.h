#pragma once

#include <string>

#include <tailgate/control/client/ControlClient.h>
#include <tailgate/crypto/Crypto.h>

#include "Registration.h"
#include "State.h"

namespace tailgate::linux_frontend
{

void RunDirectConnection(const std::string& authKey,
                         tailgate::control::client::HostInfo host,
                         const tailgate::crypto::Bytes32& machineKey,
                         const tailgate::crypto::Bytes32& nodePrivateKey,
                         const tailgate::crypto::Bytes32& discoPrivateKey,
                         bool acceptDns,
                         const std::string& exitNode,
                         int funnelPort,
                         int funnelLocalPort,
                         int exposePort,
                         DaemonStatus& status,
                         int& readyFd,
                         const std::string& followupUrl,
                         Registration& registration,
                         const std::string& reauthorizationKey);

} // namespace tailgate::linux_frontend
