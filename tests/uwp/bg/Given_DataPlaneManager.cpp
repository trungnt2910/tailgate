#include <memory>
#include <stdexcept>
#include <vector>

#include <gtest/gtest.h>

#include "manager/impl/DataPlaneManagerImpl.h"

#include "fakes/bg/manager/FakeSessionManager.h"
#include "fakes/bg/service/FakeService.h"
#include "fakes/ipn/ipnlocal/FakeNodeBackend.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_DataPlaneManager : public testing::Test
{
protected:
    void SetUp() override
    {
        m_session = std::make_shared<FakeSessionManager>();
        m_subject = std::make_unique<bg::manager::DataPlaneManagerImpl>(*m_session);
    }

    void StartService()
    {
        m_subject->Register(m_service);
        m_subject->Start(1);
    }

    void Encapsulate()
    {
        const std::vector<std::uint8_t> packet;
        const std::string relay = "relay.example.com";
        const std::string exit;
        bg::service::EncapsulationContext context{
            .Original = packet, .Node = m_node, .RelayName = relay, .ExitNode = exit};
        m_subject->Encapsulate(context);
    }

    tailgate::tests::fakes::FakeNodeBackend m_node;
    FakeService m_service;
    std::shared_ptr<FakeSessionManager> m_session;
    std::unique_ptr<bg::manager::DataPlaneManagerImpl> m_subject;
};

TEST_F(Given_DataPlaneManager, When_Started_Then_RegisteredServicesAndSessionAreNotified)
{
    constexpr bg::manager::SessionGeneration Generation = 7;
    FakeService service;
    m_subject->Register(service);

    m_subject->Start(Generation);
    ASSERT_EQ(m_session->Reports.size(), 1U);
    const auto& report = m_session->Reports.front();

    EXPECT_EQ(service.StartGeneration, Generation);
    EXPECT_EQ(report.Generation, Generation);
    EXPECT_EQ(report.Component, bg::manager::SessionComponent::DataPlane);
    EXPECT_EQ(report.Kind, bg::manager::SessionEventKind::Connecting);
}

TEST_F(Given_DataPlaneManager, When_ServiceIsRegisteredTwice_Then_ItStartsOnlyOnce)
{
    constexpr bg::manager::SessionGeneration Generation = 8;
    FakeService service;
    m_subject->Register(service);
    m_subject->Register(service);

    m_subject->Start(Generation);

    EXPECT_EQ(m_subject->ServiceCount(), 1U);
    EXPECT_EQ(service.StartGeneration, Generation);
}

TEST_F(Given_DataPlaneManager, When_RegisteringAfterStartup_Then_LogicErrorIsThrown)
{
    FakeService registered;
    FakeService late;
    m_subject->Register(registered);
    m_subject->Start(9);

    const auto action = [this, &late]
    {
        m_subject->Register(late);
    };

    EXPECT_THROW(action(), std::logic_error);
    EXPECT_EQ(m_subject->ServiceCount(), 1U);
}

TEST_F(Given_DataPlaneManager, When_Stopped_Then_EveryServiceIsStopped)
{
    FakeService first;
    FakeService second;
    m_subject->Register(first);
    m_subject->Register(second);
    m_subject->Start(10);

    m_subject->Stop();

    EXPECT_EQ(first.StopCount, 1U);
    EXPECT_EQ(second.StopCount, 1U);
}

TEST_F(Given_DataPlaneManager, When_Reset_Then_ServicesAndGenerationAreReset)
{
    FakeService service;
    m_subject->Register(service);
    m_subject->Start(11);

    m_subject->Reset();

    EXPECT_EQ(service.ResetCount, 1U);
    EXPECT_EQ(m_session->Reports.size(), 1U);
}

TEST_F(Given_DataPlaneManager, When_LocalRequestArrives_Then_RegisteredServicesReceiveIt)
{
    StartService();

    Encapsulate();

    EXPECT_EQ(m_service.EncapsulateCount, 1U);
}

TEST_F(Given_DataPlaneManager, When_LocalOutputIsQueued_Then_WorkerDrainsIt)
{
    StartService();
    m_service.LocalPending = true;
    std::vector<std::vector<std::uint8_t>> local;

    m_subject->FlushLocal(local);

    EXPECT_FALSE(m_service.LocalPending);
    EXPECT_EQ(m_service.FlushLocalCount, 1U);
}

TEST_F(Given_DataPlaneManager, When_Stopped_Then_LocalRequestsAreNotDispatched)
{
    StartService();
    m_subject->Stop();

    Encapsulate();

    EXPECT_EQ(m_service.EncapsulateCount, 0U);
}

} // namespace
} // namespace tailgate::uwp::tests
