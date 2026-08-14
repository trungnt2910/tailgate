#include "LinuxQrCode.h"

#include <stdexcept>

namespace tailgate::linux_frontend
{
namespace
{

constexpr int QuietZoneModules = 4;

bool ModuleWithQuietZone(const tailgate::qr::QrCode& code, int x, int y)
{
    x -= QuietZoneModules;
    y -= QuietZoneModules;
    return x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Module(x, y);
}

bool SupportsUnicode(std::string_view locale)
{
    return locale.ends_with(".UTF-8") || locale.ends_with(".utf8") || locale == "C.UTF-8";
}

} // namespace

QrTextFormat ResolveQrTextFormat(std::string_view requested, std::string_view locale)
{
    if (requested == "ascii")
    {
        return QrTextFormat::Ascii;
    }
    if (requested == "large")
    {
        return QrTextFormat::Large;
    }
    if (requested == "small")
    {
        return QrTextFormat::Small;
    }
    if (requested != "auto")
    {
        throw std::invalid_argument("unknown QR code format: " + std::string(requested));
    }
    return SupportsUnicode(locale) ? QrTextFormat::Small : QrTextFormat::Ascii;
}

std::string RenderQrCode(const tailgate::qr::QrCode& code, QrTextFormat format)
{
    if (code.Size <= 0 || code.Modules.size() != static_cast<std::size_t>(code.Size * code.Size))
    {
        throw std::invalid_argument("QR code matrix is invalid");
    }
    const int renderedSize = code.Size + (QuietZoneModules * 2);
    std::string result;
    if (format == QrTextFormat::Small)
    {
        for (int y = 0; y < renderedSize; y += 2)
        {
            for (int x = 0; x < renderedSize; ++x)
            {
                const bool top = ModuleWithQuietZone(code, x, y);
                const bool bottom = ModuleWithQuietZone(code, x, y + 1);
                result += top ? (bottom ? "█" : "▀") : (bottom ? "▄" : " ");
            }
            result += '\n';
        }
        return result;
    }

    const std::string_view dark = format == QrTextFormat::Ascii ? "##" : "██";
    for (int y = 0; y < renderedSize; ++y)
    {
        for (int x = 0; x < renderedSize; ++x)
        {
            result += ModuleWithQuietZone(code, x, y) ? dark : "  ";
        }
        result += '\n';
    }
    return result;
}

} // namespace tailgate::linux_frontend
