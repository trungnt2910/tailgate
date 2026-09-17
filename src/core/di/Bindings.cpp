#include "tailgate/di/Bindings.h"

#include <boost/di.hpp>

#include <tailgate/base/WallClock.h>
#include <tailgate/control/client/Connection.h>
#include <tailgate/control/client/Session.h>
#include <tailgate/crypto/Certificate.h>
#include <tailgate/crypto/Random.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/Dns.h>
#include <tailgate/hosted/PumpController.h>
#include <tailgate/hosted/ServerSession.h>
#include <tailgate/hosted/ServerWriter.h>
#include <tailgate/net/http/Client.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/ping/Tracker.h>

#include "control/client/impl/ConnectionImpl.h"
#include "control/client/impl/SessionImpl.h"
#include "crypto/impl/MbedTlsCertificate.h"
#include "crypto/impl/RandomImpl.h"
#include "derp/impl/ConnectionImpl.h"
#include "drive/driveimpl/FileSystemForLocalImpl.h"
#include "drive/driveimpl/compositedav/XmlRewriterFactoryImpl.h"
#include "drive/driveimpl/dirfs/FileSystem.h"
#include "hosted/impl/ClientSessionImpl.h"
#include "hosted/impl/PumpControllerImpl.h"
#include "hosted/impl/ServerSessionImpl.h"
#include "hosted/impl/ServerWriterImpl.h"
#include "ipn/ipnlocal/impl/LocalServicesImpl.h"
#include "net/http/impl/ClientImpl.h"
#include "net/http/impl/MessageParserFactoryImpl.h"
#include "wgengine/impl/EngineImpl.h"
#include "wgengine/impl/SessionImpl.h"
#include "wgengine/magicsock/impl/ConnectionImpl.h"
#include "wgengine/netstack/impl/Runtime.h"
#include "wgengine/netstack/impl/StackImpl.h"
#include "wgengine/ping/impl/TrackerImpl.h"

namespace tailgate::di
{

void InstallCoreBindings(Injector& injector)
{
    namespace boost_di = boost::di;
    using ControlConnectionFactory = tailgate::control::client::ConnectionFactory;
    using ControlConnectionFactoryImpl = tailgate::control::client::impl::ConnectionFactoryImpl;
    using ControlSessionFactory = tailgate::control::client::SessionFactory;
    using ControlSessionFactoryImpl = tailgate::control::client::impl::SessionFactoryImpl;
    using DerpConnectionFactory = tailgate::derp::ConnectionFactory;
    using DerpConnectionFactoryImpl = tailgate::derp::impl::ConnectionFactoryImpl;
    using Random = tailgate::crypto::Random;
    using RandomImpl = tailgate::crypto::impl::RandomImpl;
    using Engine = tailgate::wgengine::Engine;
    using EngineImpl = tailgate::wgengine::impl::EngineImpl;
    using Session = tailgate::wgengine::Session;
    using SessionImpl = tailgate::wgengine::impl::SessionImpl;
    using Connection = tailgate::wgengine::magicsock::Connection;
    using ConnectionImpl = tailgate::wgengine::magicsock::impl::ConnectionImpl;
    using PingTracker = tailgate::wgengine::ping::Tracker;
    using PingTrackerImpl = tailgate::wgengine::ping::impl::TrackerImpl;
    using HostedSession = tailgate::hosted::ClientSession;
    using HostedSessionImpl = tailgate::hosted::impl::ClientSessionImpl;
    using HostedServerFactory = tailgate::hosted::ServerSessionFactory;
    using HostedServerFactoryImpl = tailgate::hosted::impl::ServerSessionFactoryImpl;
    using PumpController = tailgate::hosted::PumpController;
    using PumpControllerImpl = tailgate::hosted::impl::PumpControllerImpl;
    using ServerWriter = tailgate::hosted::ServerWriter;
    using ServerWriterImpl = tailgate::hosted::impl::ServerWriterImpl;
    using HttpClient = tailgate::net::http::Client;
    using HttpClientImpl = tailgate::net::http::impl::ClientImpl;
    using Certificate = tailgate::crypto::Certificate;
    using CertificateImpl = tailgate::crypto::impl::MbedTlsCertificate;
    injector.install(
        boost_di::bind<tailgate::base::WallClock>(),
        boost_di::bind<ControlConnectionFactory>.to<ControlConnectionFactoryImpl>(),
        boost_di::bind<ControlSessionFactory>.to<ControlSessionFactoryImpl>(),
        boost_di::bind<DerpConnectionFactory>.to<DerpConnectionFactoryImpl>(),
        boost_di::bind<Random>.to<RandomImpl>(),
        boost_di::bind<Engine>.to<EngineImpl>(),
        boost_di::bind<Session>.to<SessionImpl>(),
        boost_di::bind<Connection>.to<ConnectionImpl>(),
        boost_di::bind<PingTracker>.to<PingTrackerImpl>(),
        boost_di::bind<tailgate::hosted::Dns>(),
        boost_di::bind<HostedSession>.to<HostedSessionImpl>(),
        boost_di::bind<HostedServerFactory>.to<HostedServerFactoryImpl>(),
        boost_di::bind<PumpController>.to<PumpControllerImpl>(),
        boost_di::bind<ServerWriter>.to<ServerWriterImpl>(),
        boost_di::bind<HttpClient>.to<HttpClientImpl>(),
        boost_di::bind<tailgate::net::http::MessageParserFactory>.to<tailgate::net::http::impl::MessageParserFactoryImpl>(),
        boost_di::bind<Certificate>.to<CertificateImpl>(),
        boost_di::bind<tailgate::drive::driveimpl::ExchangeFactory>(),
        boost_di::bind<tailgate::drive::driveimpl::PeerTransport>(),
        boost_di::bind<tailgate::drive::driveimpl::dirfs::FileSystem>(),
        boost_di::bind<tailgate::drive::FileSystemForLocal>.to<tailgate::drive::driveimpl::FileSystemForLocalImpl>(),
        boost_di::bind<tailgate::drive::driveimpl::compositedav::XmlRewriterFactory>.to<tailgate::drive::driveimpl::compositedav::XmlRewriterFactoryImpl>(),
        boost_di::bind<tailgate::hosted::Client>(),
        boost_di::bind<tailgate::ipn::ipnlocal::LocalServices>.to<tailgate::ipn::ipnlocal::impl::LocalServicesImpl>(),
        boost_di::bind<tailgate::wgengine::netstack::impl::Runtime>(),
        boost_di::bind<tailgate::wgengine::netstack::Stack>.to<tailgate::wgengine::netstack::impl::StackImpl>(),
        boost_di::bind<tailgate::hosted::Connection>());
}

} // namespace tailgate::di
