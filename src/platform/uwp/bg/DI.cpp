#include "DI.h"

#include <tailgate/control/client/HostInfoProvider.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "common/EventLoop.h"
#include "common/HostInfo.h"
#include "common/TcpPortReservationFactory.h"
#include "common/TcpSocketFactory.h"
#include "common/TimeProvider.h"
#include "common/UdpSocketFactory.h"

#include "bg/ResourceLoader.h"
#include "manager/impl/ControlPlaneManagerImpl.h"
#include "manager/impl/DataPlaneManagerImpl.h"
#include "manager/impl/SessionManagerImpl.h"
#include "plugin/NodeContext.h"

namespace tailgate::uwp::bg
{
namespace di = boost::di;
using namespace manager;
using namespace service;

PluginInjector CreatePluginInjector()
{
    auto injector = std::make_shared<tailgate::di::Injector>();
    injector->install(
        di::bind<tailgate::control::client::HostInfoProvider>.to<tailgate::uwp::HostInfoProvider>(),
        di::bind<tailgate::uwp::ResourceLoader>.to<ResourceLoader>(),
        di::bind<ControlPlaneManager>.to<ControlPlaneManagerImpl>(),
        di::bind<DataPlaneManager>.to<DataPlaneManagerImpl>(),
        di::bind<SessionManager>.to<SessionManagerImpl>(),
        di::bind<ExitNodeService>(),
        di::bind<ModeService>(),
        di::bind<PingService>());
    injector->install(di::bind<NodeContext>());
    injector->InstallSingleton<tailgate::uwp::EventLoop, tailgate::base::EventLoop>();
    injector->InstallSingleton<PacketDevice, tailgate::wgengine::tstun::Device>();
    injector->InstallSingleton<tailgate::uwp::TimeProvider, tailgate::base::TimeProvider>();
    injector->InstallSingleton<tailgate::uwp::TcpSocketFactory,
                               tailgate::types::nettype::TcpSocketFactory>();
    injector->InstallSingleton<tailgate::uwp::TcpPortReservationFactory,
                               tailgate::types::nettype::TcpPortReservationFactory>();
    injector->InstallSingleton<tailgate::uwp::UdpSocketFactory,
                               tailgate::types::nettype::UdpSocketFactory>();
    tailgate::di::InstallCoreBindings(*injector);
    return injector;
}

} // namespace tailgate::uwp::bg
