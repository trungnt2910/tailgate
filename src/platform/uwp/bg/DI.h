#pragma once

#include <boost/di.hpp>

#include "common/ResourceLoader.h"

#include "manager/ControlPlaneManager.h"
#include "manager/DataPlaneManager.h"
#include "manager/SessionManager.h"
#include "manager/TransportManager.h"
#include "service/ExitNodeService.h"
#include "service/HostedDnsService.h"
#include "service/NetworkService.h"
#include "service/PingService.h"

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

using PluginInjector = boost::di::injector<ControlPlaneManager&,
                                           DataPlaneManager&,
                                           tailgate::uwp::ResourceLoader&,
                                           SessionManager&,
                                           TransportManager&,
                                           ExitNodeService&,
                                           HostedDnsService&,
                                           NetworkService&,
                                           PingService&>;

[[nodiscard]] PluginInjector CreateRs2PluginInjector();

} // namespace tailgate::uwp::bg
