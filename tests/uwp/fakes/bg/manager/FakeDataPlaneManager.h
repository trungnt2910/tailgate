#pragma once

#include <vector>

#include "manager/DataPlaneManager.h"

namespace tailgate::uwp::tests
{

class FakeDataPlaneManager final : public bg::manager::DataPlaneManager
{
public:
    using Interface = bg::manager::DataPlaneManager;

    void Register(bg::service::IService& service) override
    {
        Services.push_back(&service);
    }

    void Start(bg::manager::SessionGeneration) override
    {
    }

    [[nodiscard]] bg::manager::DataPlaneProbe
    Probe(const std::string&, const std::string&, const std::string&) override
    {
        return ProbeResult;
    }

    void RememberProbe(const std::string&, const bg::manager::DataPlaneProbe&) override
    {
    }

    void InvalidateProbe(const std::string&) override
    {
    }

    void Connect() override
    {
    }

    void Stop() override
    {
    }

    void Reset() override
    {
    }

    void Encapsulate(bg::service::EncapsulationContext&) override
    {
    }

    void Decapsulate(bg::service::DecapsulationContext&) override
    {
    }

    void FlushLocal(std::vector<std::vector<std::uint8_t>>&) override
    {
    }

    [[nodiscard]] std::size_t ServiceCount() const override
    {
        return Services.size();
    }

    bg::manager::DataPlaneProbe ProbeResult;
    std::vector<bg::service::IService*> Services;
};

} // namespace tailgate::uwp::tests
