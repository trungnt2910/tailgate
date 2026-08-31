#pragma once

#include <memory>

#include <boost/di.hpp>

#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/hosted/Connection.h>

#include "common/ResourceLoader.h"

#include "manager/ControlPlaneManager.h"
#include "manager/DataPlaneManager.h"
#include "manager/SessionManager.h"
#include "manager/TransportManager.h"
#include "service/ExitNodeService.h"
#include "service/HostedDnsService.h"
#include "service/NetworkService.h"
#include "service/PingService.h"

#include "tstun/PacketDevice.h"

namespace tailgate::uwp::bg
{

using manager::ControlPlaneManager;
using manager::DataPlaneManager;
using manager::SessionManager;
using manager::TransportManager;
using service::ExitNodeService;
using service::HostedDnsService;
using service::NetworkService;
using service::PingService;

using PluginInjector = std::unique_ptr<tailgate::di::Injector>;

[[nodiscard]] PluginInjector CreateRs2PluginInjector();

} // namespace tailgate::uwp::bg
