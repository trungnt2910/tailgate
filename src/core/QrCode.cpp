#include "tailgate/QrCode.h"

#include <format>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

#include <zint.h>

namespace tailgate
{
namespace
{

constexpr int PackedModuleByteShift = 3;
constexpr int PackedModuleBitMask = 0x07;

} // namespace

bool QrCode::Module(int x, int y) const
{
    if (x < 0 || y < 0 || x >= Size || y >= Size)
    {
        throw std::out_of_range("QR code module coordinates are outside the matrix.");
    }
    return Modules[static_cast<std::size_t>(y * Size + x)] != 0;
}

QrCode EncodeQrCode(std::string_view text)
{
    if (text.empty())
    {
        throw std::invalid_argument("QR code text must not be empty.");
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        throw std::length_error("QR code text is too long.");
    }
    const auto deleteSymbol = [](zint_symbol* symbol)
    {
        ZBarcode_Delete(symbol);
    };
    std::unique_ptr<zint_symbol, decltype(deleteSymbol)> symbol(ZBarcode_Create(), deleteSymbol);
    if (!symbol)
    {
        throw std::runtime_error("Zint could not allocate a QR code symbol.");
    }
    constexpr int MediumErrorCorrection = 2;
    symbol->symbology = BARCODE_QRCODE;
    symbol->option_1 = MediumErrorCorrection;
    symbol->input_mode = UNICODE_MODE;
    symbol->warn_level = WARN_FAIL_ALL;
    const int status = ZBarcode_Encode(symbol.get(),
                                       reinterpret_cast<const unsigned char*>(text.data()),
                                       static_cast<int>(text.size()));
    if (status != 0)
    {
        throw std::runtime_error(std::format("Zint QR code error: {}.", symbol->errtxt));
    }
    if (symbol->rows <= 0 || symbol->rows != symbol->width)
    {
        throw std::runtime_error("Zint returned a non-square QR code matrix.");
    }

    QrCode result;
    result.Size = symbol->width;
    result.Modules.reserve(static_cast<std::size_t>(result.Size * result.Size));
    for (int y = 0; y < result.Size; ++y)
    {
        for (int x = 0; x < result.Size; ++x)
        {
            const auto packed = symbol->encoded_data[y][x >> PackedModuleByteShift];
            const bool dark = ((packed >> (x & PackedModuleBitMask)) & 1) != 0;
            result.Modules.push_back(dark ? 1 : 0);
        }
    }
    return result;
}

} // namespace tailgate
