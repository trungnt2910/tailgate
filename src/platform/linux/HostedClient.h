#pragma once

#include <cstddef>
#include <string>

#include <tailgate/control/client/ControlClient.h>
#include <tailgate/crypto/Crypto.h>

#include "Registration.h"
#include "State.h"

namespace tailgate::linux_frontend
{

void RunHostedClient(const std::string& url,
                     const std::string& authKey,
                     const std::string& followupUrl,
                     const tailgate::control::client::HostInfo& host,
                     const tailgate::crypto::Bytes32& machinePrivateKey,
                     const tailgate::crypto::Bytes32& nodePrivateKey,
                     const tailgate::crypto::Bytes32& discoPrivateKey,
                     bool acceptDns,
                     const std::string& exitNode,
                     DaemonStatus& status,
                     int& readyFd,
                     std::size_t addressAttempt,
                     Registration& registration,
                     const std::string& reauthorizationKey);

} // namespace tailgate::linux_frontend
