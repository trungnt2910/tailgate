#include "ScreenDiff.h"

#include <algorithm>
#include <cstddef>
#include <limits>

namespace tailgate::uwp::tests
{

namespace
{

constexpr std::size_t BytesPerPixel = 4;
constexpr std::uint8_t TransparentChannel = 0;
constexpr std::uint8_t OpaqueChannel = 255;
constexpr std::uint8_t MagentaBlueChannel = 255;
constexpr std::uint8_t MagentaGreenChannel = 0;
constexpr std::uint8_t MagentaRedChannel = 255;
constexpr std::wstring_view PngExtension = L".png";

enum class BgraChannel : std::size_t
{
    Blue,
    Green,
    Red,
    Alpha,
};

[[nodiscard]] constexpr std::size_t ChannelOffset(std::size_t pixelOffset,
                                                  BgraChannel channel) noexcept
{
    return pixelOffset + static_cast<std::size_t>(channel);
}

[[nodiscard]] std::optional<std::size_t> PixelBufferSize(std::uint32_t width,
                                                         std::uint32_t height) noexcept
{
    constexpr auto MaximumSize = std::numeric_limits<std::size_t>::max();
    if (height != 0 && width > MaximumSize / height)
    {
        return std::nullopt;
    }
    const auto pixelCount = static_cast<std::size_t>(width) * height;
    if (pixelCount > MaximumSize / BytesPerPixel)
    {
        return std::nullopt;
    }
    return pixelCount * BytesPerPixel;
}

[[nodiscard]] bool HasValidBuffer(const ScreenDiff::Pixels& image) noexcept
{
    const auto size = PixelBufferSize(image.width, image.height);
    return size.has_value() && *size == image.bgra.size();
}

[[nodiscard]] std::size_t
PixelOffset(std::uint32_t x, std::uint32_t y, std::uint32_t width) noexcept
{
    return (static_cast<std::size_t>(y) * width + x) * BytesPerPixel;
}

} // namespace

bool ScreenDiff::Matches(std::wstring_view fileName, std::wstring_view testName) noexcept
{
    return !testName.empty() && fileName.starts_with(testName) && fileName.ends_with(PngExtension);
}

std::optional<ScreenDiff::Pixels> ScreenDiff::TryCreateDiff(const Pixels& reference,
                                                            const Pixels& actual) noexcept
{
    if (!HasValidBuffer(reference) || !HasValidBuffer(actual))
    {
        return std::nullopt;
    }

    const std::uint32_t width = std::max(reference.width, actual.width);
    const std::uint32_t height = std::max(reference.height, actual.height);
    const auto size = PixelBufferSize(width, height);
    if (!size.has_value())
    {
        return std::nullopt;
    }

    Pixels difference{
        .width = width,
        .height = height,
        .bgra = std::vector<std::uint8_t>(*size, TransparentChannel),
    };
    for (std::uint32_t y = 0; y < height; ++y)
    {
        for (std::uint32_t x = 0; x < width; ++x)
        {
            const bool inReference = x < reference.width && y < reference.height;
            const bool inActual = x < actual.width && y < actual.height;
            bool isDifferent = inReference != inActual;
            if (inReference && inActual)
            {
                const auto referenceOffset = PixelOffset(x, y, reference.width);
                const auto actualOffset = PixelOffset(x, y, actual.width);
                isDifferent = !std::equal(reference.bgra.begin() + referenceOffset,
                                          reference.bgra.begin() + referenceOffset + BytesPerPixel,
                                          actual.bgra.begin() + actualOffset);
            }
            if (!isDifferent)
            {
                continue;
            }
            const auto offset = PixelOffset(x, y, width);
            difference.bgra[ChannelOffset(offset, BgraChannel::Blue)] = MagentaBlueChannel;
            difference.bgra[ChannelOffset(offset, BgraChannel::Green)] = MagentaGreenChannel;
            difference.bgra[ChannelOffset(offset, BgraChannel::Red)] = MagentaRedChannel;
            difference.bgra[ChannelOffset(offset, BgraChannel::Alpha)] = OpaqueChannel;
        }
    }
    return difference;
}

} // namespace tailgate::uwp::tests
