#pragma once

#include <algorithm>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include <tailgate/crypto/Random.h>

namespace tailgate::tests::fakes
{

class FakeRandom final : public tailgate::crypto::Random
{
public:
    explicit FakeRandom(std::vector<std::uint8_t> bytes) : m_bytes(std::move(bytes))
    {
    }

    void Fill(std::span<std::uint8_t> output) override
    {
        std::ranges::copy(m_bytes, output.begin());
        ++FillCount;
    }

    std::size_t FillCount{};

private:
    std::vector<std::uint8_t> m_bytes;
};

} // namespace tailgate::tests::fakes
