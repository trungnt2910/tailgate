#pragma once

#include <mutex>
#include <vector>

#include "manager/DataPlaneManager.h"

namespace tailgate::uwp::bg::manager
{

class DataPlaneManagerImpl final : public DataPlaneManager
{
public:
    explicit DataPlaneManagerImpl(SessionManager& sessionManager);

    void Register(service::IService& service) override;
    void Start(SessionGeneration generation) override;
    [[nodiscard]] DataPlaneProbe
    Probe(const std::string& server, const std::string& host, const std::string& service) override;
    void RememberProbe(const std::string& server, const DataPlaneProbe& probe) override;
    void InvalidateProbe(const std::string& server) override;
    void Connect() override;
    void Stop() override;
    void Reset() override;
    void Encapsulate(service::EncapsulationContext& context) override;
    void Decapsulate(service::DecapsulationContext& context) override;
    void FlushLocal(std::vector<std::vector<std::uint8_t>>& localOutput) override;

    [[nodiscard]] std::size_t ServiceCount() const override;

private:
    void Report(SessionEventKind kind);

    SessionManager& m_sessionManager;
    mutable std::mutex m_mutex;
    std::vector<service::IService*> m_services;
    SessionGeneration m_generation = 0;
    bool m_started = false;
};

} // namespace tailgate::uwp::bg::manager
