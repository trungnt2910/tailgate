#include "DI.h"

#include <tailgate/control/client/HostInfoProvider.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "common/HostInfo.h"
#include "common/TcpSocketFactory.h"

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
    auto injector = std::make_unique<tailgate::di::Injector>();
    injector->install(
        di::bind<tailgate::control::client::HostInfoProvider>.to<tailgate::uwp::HostInfoProvider>(),
        di::bind<tailgate::uwp::ResourceLoader>.to<ResourceLoader>(),
        di::bind<ControlPlaneManager>.to<ControlPlaneManagerImpl>(),
        di::bind<DataPlaneManager>.to<DataPlaneManagerImpl>(),
        di::bind<SessionManager>.to<SessionManagerImpl>(),
        di::bind<TransportManager>.to<Rs2TransportManagerImpl>(),
        di::bind<ExitNodeService>(),
        di::bind<HostedDnsService>(),
        di::bind<NetworkService>(),
        di::bind<PingService>());
    injector->InstallSingleton<PacketDevice, tailgate::wgengine::tstun::Device>();
    injector->InstallSingleton<tailgate::uwp::TcpSocketFactory,
                               tailgate::types::nettype::TcpSocketFactory>();
    tailgate::di::InstallCoreBindings(*injector);
    return injector;
}

} // namespace tailgate::uwp::bg
