#pragma once

#include <boost/di.hpp>

#include <tailgate/base/EventLoop.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/control/client/HostInfoProvider.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "fakes/base/FakeEventLoop.h"
#include "fakes/base/FakeTimeProvider.h"
#include "fakes/control/client/FakeHostInfoProvider.h"
#include "fakes/types/nettype/FakeTcpSocket.h"
#include "fakes/types/nettype/FakeUdpSocket.h"
#include "fakes/wgengine/tstun/FakeDevice.h"

namespace tailgate::tests::fakes
{

inline void InstallFakeNetworkBindings(tailgate::di::Injector& injector)
{
    namespace boost_di = boost::di;
    injector.install(
        boost_di::bind<tailgate::base::TimeProvider>.to<FakeTimeProvider>(),
        boost_di::bind<tailgate::base::EventLoop>.to<FakeEventLoop>(),
        boost_di::bind<tailgate::control::client::HostInfoProvider>.to<FakeHostInfoProvider>(),
        boost_di::bind<tailgate::types::nettype::UdpSocketFactory>.to<FakeUdpSocketFactory>(),
        boost_di::bind<tailgate::types::nettype::TcpSocketFactory>.to<FakeTcpSocketFactory>());
    injector.InstallSingleton<FakeDevice, tailgate::wgengine::tstun::Device>();
    tailgate::di::InstallCoreBindings(injector);
}

} // namespace tailgate::tests::fakes
