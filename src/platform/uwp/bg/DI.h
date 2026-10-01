#pragma once

#include <memory>

#include <tailgate/base/EventLoop.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/hosted/Connection.h>
#include <tailgate/ipn/ipnlocal/DnsForwarder.h>
#include <tailgate/ipn/ipnlocal/LocalServices.h>
#include <tailgate/wgengine/PeerProtocol.h>

#include "common/ResourceLoader.h"

#include "manager/ControlPlaneManager.h"
#include "manager/DataPlaneManager.h"
#include "manager/SessionManager.h"
#include "service/ExitNodeService.h"
#include "service/ModeService.h"
#include "service/PingService.h"

#include "tstun/PacketDevice.h"

namespace tailgate::uwp::bg
{

using manager::ControlPlaneManager;
using manager::DataPlaneManager;
using manager::SessionManager;
using service::ExitNodeService;
using service::ModeService;
using service::PingService;

using PluginInjector = std::shared_ptr<tailgate::di::Injector>;

// One graph per plugin. NodeContext explicitly resets account and transport state.
[[nodiscard]] PluginInjector CreatePluginInjector();

} // namespace tailgate::uwp::bg
