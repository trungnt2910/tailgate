#include <tailgate/base/Strings.h>

#include <cctype>

namespace tailgate::base
{

std::string_view TrimEnd(std::string_view value) noexcept
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0)
    {
        value.remove_suffix(1);
    }
    return value;
}

} // namespace tailgate::base
