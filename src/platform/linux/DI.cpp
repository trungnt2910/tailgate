#include "DI.h"

#include <boost/di.hpp>

#include <tailgate/base/EventLoop.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/control/client/HostInfoProvider.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "PacketDescriptorProvider.h"
#include "event/EventRegistry.h"
#include "impl/EventLoop.h"
#include "impl/HostInfoProvider.h"
#include "impl/TcpSocketFactory.h"
#include "impl/TimeProvider.h"
#include "impl/TunDevice.h"
#include "impl/UdpSocketFactory.h"

namespace tailgate::linux_frontend
{

void InstallBindings(tailgate::di::Injector& injector)
{
    namespace boost_di = boost::di;
    namespace linux_event = tailgate::linux_frontend::event;
    namespace linux_impl = tailgate::linux_frontend::impl;
    injector.install(
        boost_di::bind<PacketDescriptorProvider>(),
        boost_di::bind<linux_event::EventRegistry>(),
        boost_di::bind<tailgate::control::client::HostInfoProvider>.to<linux_impl::HostInfoProvider>(),
        boost_di::bind<tailgate::base::TimeProvider>.to<linux_impl::TimeProvider>(),
        boost_di::bind<tailgate::base::EventLoop>.to<linux_impl::EventLoop>(),
        boost_di::bind<tailgate::types::nettype::UdpSocketFactory>.to<linux_impl::UdpSocketFactory>(),
        boost_di::bind<tailgate::types::nettype::TcpSocketFactory>.to<linux_impl::TcpSocketFactory>(),
        boost_di::bind<tailgate::wgengine::tstun::Device>.to<linux_impl::TunDevice>());
    tailgate::di::InstallCoreBindings(injector);
}

} // namespace tailgate::linux_frontend
