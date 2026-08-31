#pragma once

#include <cstdint>
#include <span>

namespace tailgate::crypto
{

class Random
{
public:
    virtual ~Random();

    virtual void Fill(std::span<std::uint8_t> output) = 0;

protected:
    Random() = default;
};

} // namespace tailgate::crypto
