#include "tailgate/crypto/PrefixedKey.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace tailgate::crypto
{

std::optional<Bytes32> PrefixedKey::TryParse(std::string_view text, std::string_view prefix)
{
    if (!text.starts_with(prefix))
    {
        return std::nullopt;
    }
    const auto encoded = text.substr(prefix.size());
    constexpr std::size_t EncodedSize = Bytes32{}.size() * 2;
    if (encoded.size() != EncodedSize || !std::ranges::all_of(encoded,
                                                              [](unsigned char character)
                                                              {
                                                                  return std::isxdigit(character) !=
                                                                         0;
                                                              }))
    {
        return std::nullopt;
    }
    const auto bytes = HexToBytes(std::string(encoded));
    Bytes32 result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

} // namespace tailgate::crypto
