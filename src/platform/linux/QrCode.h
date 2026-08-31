#pragma once

#include <string>
#include <string_view>

#include <tailgate/qr/QrCode.h>

namespace tailgate::linux_frontend
{

enum class QrTextFormat
{
    Ascii,
    Large,
    Small,
};

[[nodiscard]] QrTextFormat ResolveQrTextFormat(std::string_view requested, std::string_view locale);
[[nodiscard]] std::string RenderQrCode(const tailgate::qr::QrCode& code, QrTextFormat format);

} // namespace tailgate::linux_frontend
