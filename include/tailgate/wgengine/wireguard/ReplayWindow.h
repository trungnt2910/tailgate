#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace tailgate::wgengine::wireguard
{

class ReplayWindow
{
public:
    static constexpr std::size_t WindowSize = 8192;

    [[nodiscard]] bool Accept(std::uint64_t counter);
    void Reset();

private:
    static constexpr std::size_t BitsPerWord = 64;
    static constexpr std::size_t WordCount = WindowSize / BitsPerWord;

    [[nodiscard]] bool IsSet(std::uint64_t counter) const;
    void Set(std::uint64_t counter);
    void Clear(std::uint64_t counter);

    std::array<std::uint64_t, WordCount> m_bitmap{};
    std::uint64_t m_highest = 0;
    bool m_initialized = false;
};

} // namespace tailgate::wgengine::wireguard
