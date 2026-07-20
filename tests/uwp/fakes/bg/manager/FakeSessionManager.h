#pragma once

#include <cstddef>
#include <optional>
#include <vector>

#include "manager/SessionManager.h"

namespace tailgate::uwp::tests
{

class FakeSessionManager final : public bg::manager::SessionManager
{
public:
    [[nodiscard]] bg::manager::SessionGeneration BeginConnect() override
    {
        return ++GenerationValue;
    }

    void Report(const bg::manager::SessionEvent& event) override
    {
        Reports.push_back(event);
    }

    void Notify(bg::manager::SessionGeneration,
                const bg::manager::ForegroundConnectionNotification&) override
    {
        ++NotifyCount;
    }

    void StartForegroundMonitor(const std::string&,
                                bg::manager::ForegroundCancellationHandler) override
    {
        ++StartForegroundMonitorCount;
    }

    void StopForegroundMonitor() override
    {
        ++StopForegroundMonitorCount;
    }

    void WriteState(const control::NetworkConfig&) override
    {
        ++WriteStateCount;
    }

    void SignalStateChanged() override
    {
        ++SignalStateChangedCount;
    }

    void BeginStop() override
    {
        StateValue = bg::manager::SessionState::Stopping;
    }

    void CompleteStop() override
    {
        StateValue = bg::manager::SessionState::Stopped;
    }

    void Reset() override
    {
        StateValue = bg::manager::SessionState::Stopped;
    }

    [[nodiscard]] bg::manager::SessionGeneration Generation() const override
    {
        return GenerationValue;
    }

    [[nodiscard]] bg::manager::SessionState State() const override
    {
        return StateValue;
    }

    bg::manager::SessionGeneration GenerationValue = 0;
    bg::manager::SessionState StateValue = bg::manager::SessionState::Stopped;
    std::vector<bg::manager::SessionEvent> Reports;
    std::size_t NotifyCount = 0;
    std::size_t StartForegroundMonitorCount = 0;
    std::size_t StopForegroundMonitorCount = 0;
    std::size_t WriteStateCount = 0;
    std::size_t SignalStateChangedCount = 0;
};

} // namespace tailgate::uwp::tests
