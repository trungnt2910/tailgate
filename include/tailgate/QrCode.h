#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace tailgate
{

struct QrCode
{
    int Size = 0;
    std::vector<std::uint8_t> Modules;

    [[nodiscard]] bool Module(int x, int y) const;
};

[[nodiscard]] QrCode EncodeQrCode(std::string_view text);

} // namespace tailgate
