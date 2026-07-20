#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace tailgate::uwp::tests
{

class ScreenDiff final
{
public:
    struct Pixels final
    {
        std::uint32_t width;
        std::uint32_t height;
        std::vector<std::uint8_t> bgra;
    };

    ScreenDiff() = delete;

    [[nodiscard]] static bool Matches(std::wstring_view fileName,
                                      std::wstring_view testName) noexcept;

    [[nodiscard]] static std::optional<Pixels> TryCreateDiff(const Pixels& reference,
                                                             const Pixels& actual) noexcept;
};

} // namespace tailgate::uwp::tests
