#pragma once

namespace tailgate::uwp
{

class Glyphs final
{
public:
    Glyphs() = delete;

    inline static constexpr wchar_t CheckMark[] = L"\xE73E";
    inline static constexpr wchar_t ChevronDown[] = L"\xE70D";
    inline static constexpr wchar_t ChevronRight[] = L"\xE76C";
    inline static constexpr wchar_t Copy[] = L"\xE8C8";
    inline static constexpr wchar_t ErrorBadge12[] = L"\xEDAE";
    inline static constexpr wchar_t Forward[] = L"\xE72A";
    inline static constexpr wchar_t Link[] = L"\xE71B";
    inline static constexpr wchar_t Network[] = L"\xE7E8";
    inline static constexpr wchar_t Person[] = L"\xE77B";
    inline static constexpr wchar_t SpeedHigh[] = L"\xEC4A";
    inline static constexpr wchar_t Warning[] = L"\xE7BA";
};

} // namespace tailgate::uwp
