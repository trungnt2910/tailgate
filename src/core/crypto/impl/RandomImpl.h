#pragma once

#include <tailgate/crypto/Random.h>

namespace tailgate::crypto::impl
{

class RandomImpl final : public Random
{
public:
    void Fill(std::span<std::uint8_t> output) override;
};

} // namespace tailgate::crypto::impl
