#include <memory>

#include <gtest/gtest.h>

#include <tailgate/drive/FileSystemForLocal.h>

#include "drive/driveimpl/PeerTransport.h"
#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/drive/FakeTcpStack.h"

namespace tailgate::tests
{

TEST(Given_FileSystemForLocalImpl,
     When_TransportIsResolvedByReferenceAndOwner_Then_InstanceIsShared)
{
    di::Injector injector;
    fakes::InstallFakeNetworkBindings(injector);
    injector.InstallSingleton<fakes::FakeTcpStack, wgengine::netstack::Stack>();

    auto& borrowed = injector.create<drive::driveimpl::PeerTransport&>();
    const auto owned = injector.create<std::shared_ptr<drive::driveimpl::PeerTransport>>();

    EXPECT_EQ(&borrowed, owned.get());
}

TEST(Given_FileSystemForLocalImpl,
     When_InjectorIsDestroyedBeforeStop_Then_TransportSurvivesUntilFileSystemIsReleased)
{
    auto injector = std::make_unique<di::Injector>();
    fakes::InstallFakeNetworkBindings(*injector);
    injector->InstallSingleton<fakes::FakeTcpStack, wgengine::netstack::Stack>();
    auto fileSystem = injector->create<std::shared_ptr<drive::FileSystemForLocal>>();
    fileSystem->SetNetworkConfig({});
    auto transport = injector->create<std::shared_ptr<drive::driveimpl::PeerTransport>>();
    const std::weak_ptr<drive::driveimpl::PeerTransport> lifetime = transport;
    auto catalog = std::make_shared<drive::driveimpl::Catalog>();
    catalog->Access = true;
    catalog->Remotes.emplace_back();
    transport->SetCatalog(catalog);
    const auto idlePeer = std::make_shared<fakes::FakeTcpStreamState>();
    transport->Release(catalog->Remotes.front(), std::make_unique<fakes::FakeTcpStream>(idlePeer));
    const auto activeClient = std::make_shared<fakes::FakeTcpStreamState>();
    fileSystem->HandleConn(std::make_unique<fakes::FakeTcpStream>(activeClient));
    ASSERT_TRUE(transport->NextDeadline().has_value());
    ASSERT_FALSE(activeClient->Aborted);

    transport.reset();
    injector.reset();
    const bool retained = !lifetime.expired();
    const bool idleSurvived = !idlePeer->Aborted;
    fileSystem->Stop();
    const bool retainedAfterStop = !lifetime.expired();
    fileSystem.reset();

    EXPECT_TRUE(retained);
    EXPECT_TRUE(idleSurvived);
    EXPECT_TRUE(idlePeer->Aborted);
    EXPECT_TRUE(activeClient->Aborted);
    EXPECT_TRUE(retainedAfterStop);
    EXPECT_TRUE(lifetime.expired());
}

} // namespace tailgate::tests
