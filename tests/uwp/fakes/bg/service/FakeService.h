#pragma once

#include <cstddef>
#include <optional>

#include "service/IService.h"

namespace tailgate::uwp::tests
{

class FakeService final : public bg::service::IService
{
public:
    void Start(bg::manager::SessionGeneration generation) override
    {
        StartGeneration = generation;
    }

    void Stop() override
    {
        ++StopCount;
    }

    void Reset() override
    {
        ++ResetCount;
    }

    void Encapsulate(bg::service::EncapsulationContext&) override
    {
        ++EncapsulateCount;
    }

    void Decapsulate(bg::service::DecapsulationContext&) override
    {
        ++DecapsulateCount;
    }

    void FlushLocal(std::vector<std::vector<std::uint8_t>>&) override
    {
        ++FlushLocalCount;
    }

    std::optional<bg::manager::SessionGeneration> StartGeneration;
    std::size_t StopCount = 0;
    std::size_t ResetCount = 0;
    std::size_t EncapsulateCount = 0;
    std::size_t DecapsulateCount = 0;
    std::size_t FlushLocalCount = 0;
};

} // namespace tailgate::uwp::tests
