#include <memory>
#include <optional>
#include <stdexcept>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "manager/impl/DataPlaneManagerImpl.h"

#include "fakes/bg/manager/FakeSessionManager.h"
#include "fakes/bg/service/FakeService.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_DataPlaneManager : public testing::Test
{
protected:
    void SetUp() override
    {
        m_session = std::make_shared<FakeSessionManager>();
        auto injector = di::make_injector(di::bind<bg::manager::SessionManager>.to(
            [this](const auto&) -> bg::manager::SessionManager&
            {
                return *m_session;
            }));
        m_subject = injector.create<std::unique_ptr<bg::manager::DataPlaneManagerImpl>>();
    }

    std::shared_ptr<FakeSessionManager> m_session;
    std::unique_ptr<bg::manager::DataPlaneManagerImpl> m_subject;
};

TEST_F(Given_DataPlaneManager, When_Started_Then_RegisteredServicesAndSessionAreNotified)
{
    constexpr bg::manager::SessionGeneration Generation = 7;
    FakeService service;
    m_subject->Register(service);

    m_subject->Start(Generation);

    const auto report = m_session->Reports.empty() ? std::optional<bg::manager::SessionEvent>{}
                                                   : std::optional(m_session->Reports.front());
    EXPECT_EQ(service.StartGeneration, Generation);
    EXPECT_EQ(m_session->Reports.size(), 1U);
    EXPECT_EQ(report.value_or(bg::manager::SessionEvent{}).Generation, Generation);
    EXPECT_EQ(report.value_or(bg::manager::SessionEvent{}).Component,
              bg::manager::SessionComponent::DataPlane);
    EXPECT_EQ(report.value_or(bg::manager::SessionEvent{}).Kind,
              bg::manager::SessionEventKind::Connecting);
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

} // namespace
} // namespace tailgate::uwp::tests
