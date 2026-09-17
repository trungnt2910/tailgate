#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/hosted/Pump.h>

#include "manager/impl/DataPlaneManagerImpl.h"

#include "fakes/bg/manager/FakeSessionManager.h"
#include "fakes/bg/service/FakeService.h"
#include "fakes/di/FakeNetworkBindings.h"

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
        m_core = std::make_unique<tailgate::di::Injector>();
        tailgate::tests::fakes::InstallFakeNetworkBindings(*m_core);
        auto injector =
            di::make_injector(di::bind<bg::manager::SessionManager>.to(
                                  [this](const auto&) -> bg::manager::SessionManager&
                                  {
                                      return *m_session;
                                  }),
                              di::bind<tailgate::hosted::PumpController>.to(
                                  [this](const auto&) -> tailgate::hosted::PumpController&
                                  {
                                      return m_core->create<tailgate::hosted::PumpController&>();
                                  }));
        m_subject = injector.create<std::unique_ptr<bg::manager::DataPlaneManagerImpl>>();
    }

    void StartPumpService()
    {
        m_subject->Register(m_service);
        m_subject->Start(1);
    }

    void Encapsulate()
    {
        const std::vector<std::uint8_t> packet;
        const std::string relay = "relay.example.com";
        bg::service::EncapsulationContext context{.Original = packet,
                                                  .Client =
                                                      m_core->create<tailgate::hosted::Client&>(),
                                                  .RelayName = relay,
                                                  .RemoteOutput = m_output};
        m_subject->Encapsulate(context);
    }

    std::optional<tailgate::hosted::PumpSchedule> Schedule()
    {
        tailgate::hosted::Decoder decoder;
        decoder.Feed(m_output);
        const auto frame = decoder.Next();
        if (!frame || frame->Type() != tailgate::hosted::MessageType::PumpSchedule ||
            decoder.Next())
        {
            return std::nullopt;
        }
        return tailgate::hosted::TryDecodePumpSchedule(frame->Payload());
    }

    FakeService m_service;
    std::vector<std::uint8_t> m_output;
    std::unique_ptr<tailgate::di::Injector> m_core;
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

TEST_F(Given_DataPlaneManager, When_LocalOutputIsQueued_Then_ImmediateCallbackIsRequested)
{
    StartPumpService();
    m_service.LocalPending = true;

    Encapsulate();
    const auto schedule = Schedule();

    EXPECT_TRUE(schedule.has_value());
    EXPECT_EQ(schedule.value_or(tailgate::hosted::PumpSchedule{}).Delay,
              std::chrono::milliseconds::zero());
}

TEST_F(Given_DataPlaneManager, When_OutputAlreadyHasScheduledCallback_Then_DuplicateIsSuppressed)
{
    StartPumpService();
    m_service.LocalPending = true;
    Encapsulate();
    ASSERT_TRUE(Schedule().has_value());
    m_output.clear();

    Encapsulate();

    EXPECT_TRUE(m_output.empty());
}

TEST_F(Given_DataPlaneManager, When_NormalIncomingCallbackDrainsOutput_Then_NoImmediatePumpIsAdded)
{
    StartPumpService();
    m_service.LocalPending = true;
    std::vector<std::vector<std::uint8_t>> local;

    m_subject->FlushLocal(local, m_output);

    EXPECT_TRUE(m_output.empty());
    EXPECT_FALSE(m_service.LocalPending);
    EXPECT_EQ(m_service.FlushLocalCount, 1U);
}

TEST_F(Given_DataPlaneManager, When_CoreHasDeadline_Then_ServerIsAskedToWakeAtThatDeadline)
{
    StartPumpService();
    const auto now = m_core->create<tailgate::base::TimeProvider&>().Now();
    m_service.Deadline = now + std::chrono::milliseconds(1200);

    Encapsulate();
    const auto schedule = Schedule();

    EXPECT_TRUE(schedule.has_value());
    EXPECT_EQ(schedule.value_or(tailgate::hosted::PumpSchedule{}).Delay,
              std::chrono::milliseconds(1200));
}

TEST_F(Given_DataPlaneManager,
       When_IncomingTrafficDrainsScheduledOutput_Then_ObsoletePumpIsCancelled)
{
    StartPumpService();
    m_service.LocalPending = true;
    Encapsulate();
    ASSERT_TRUE(Schedule().has_value());
    m_output.clear();
    std::vector<std::vector<std::uint8_t>> local;

    m_subject->FlushLocal(local, m_output);
    const auto schedule = Schedule();

    EXPECT_TRUE(schedule.has_value());
    EXPECT_FALSE(schedule.value_or(tailgate::hosted::PumpSchedule{}).Delay.has_value());
}

TEST_F(Given_DataPlaneManager, When_DataPlaneIsStopped_Then_NoCallbackIsScheduled)
{
    StartPumpService();
    m_subject->Stop();
    m_service.LocalPending = true;

    Encapsulate();

    EXPECT_TRUE(m_output.empty());
}

} // namespace
} // namespace tailgate::uwp::tests
