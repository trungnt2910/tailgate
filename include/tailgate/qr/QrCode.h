#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace tailgate::qr
{

class QrCode
{
public:
    [[nodiscard]] static QrCode Encode(std::string_view text);
    [[nodiscard]] bool Module(int x, int y) const;
    [[nodiscard]] int Size() const noexcept;

private:
    QrCode(int size, std::vector<std::uint8_t> modules);

    int m_size = 0;
    std::vector<std::uint8_t> m_modules;
};

} // namespace tailgate::qr
