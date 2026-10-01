#pragma once

#include <optional>
#include <string_view>

#include <tailgate/crypto/Crypto.h>

namespace tailgate::crypto
{

class PrefixedKey final
{
public:
    [[nodiscard]] static std::optional<Bytes32> TryParse(std::string_view text,
                                                         std::string_view prefix);
};

} // namespace tailgate::crypto
