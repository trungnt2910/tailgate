#include "DI.h"

#include <boost/di/extension/scopes/scoped.hpp>

#include <tailgate/di/Bindings.h>

#include "bg/ResourceLoader.h"
#include "manager/impl/ControlPlaneManagerImpl.h"
#include "manager/impl/DataPlaneManagerImpl.h"
#include "manager/impl/Rs2TransportManagerImpl.h"
#include "manager/impl/SessionManagerImpl.h"

namespace tailgate::uwp::bg
{
namespace di = boost::di;
using namespace manager;
using namespace service;

PluginInjector CreateRs2PluginInjector()
{
    return di::make_injector(
        tailgate::di::Bindings(),
        di::bind<tailgate::uwp::ResourceLoader>.to<ResourceLoader>().in(di::extension::scoped),
        di::bind<ControlPlaneManager>.to<ControlPlaneManagerImpl>().in(di::extension::scoped),
        di::bind<DataPlaneManager>.to<DataPlaneManagerImpl>().in(di::extension::scoped),
        di::bind<SessionManager>.to<SessionManagerImpl>().in(di::extension::scoped),
        di::bind<TransportManager>.to<Rs2TransportManagerImpl>().in(di::extension::scoped),
        di::bind<ExitNodeService>.in(di::extension::scoped),
        di::bind<HostedDnsService>.in(di::extension::scoped),
        di::bind<NetworkService>.in(di::extension::scoped),
        di::bind<PingService>.in(di::extension::scoped));
}

} // namespace tailgate::uwp::bg
