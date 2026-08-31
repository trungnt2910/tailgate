#pragma once

#include <functional>
#include <string>

#include <tailgate/base/ByteStream.h>
#include <tailgate/control/client/Connection.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/ServerSession.h>

#include "HostedConnectionRegistry.h"

namespace tailgate::linux_frontend
{

void RunHostedServer(tailgate::hosted::ServerSessionFactory& sessionFactory,
                     HostedConnectionRegistry& hostedConnections,
                     tailgate::control::client::Connection& control,
                     tailgate::base::ByteStream& stream,
                     const std::string& expectedDomain,
                     const std::string& relayHostName,
                     const std::string& relayHostAddress,
                     const tailgate::crypto::Bytes32& relayPrivateKey,
                     const tailgate::crypto::Bytes32& relayPublicKey,
                     const std::function<void()>& closeConnection,
                     const std::function<void()>& markIdentityVerified);

} // namespace tailgate::linux_frontend
