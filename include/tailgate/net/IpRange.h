#pragma once

#include <optional>
#include <string_view>

#include <tailgate/net/IpAddress.h>

namespace tailgate::net
{

class IpRange final
{
public:
    [[nodiscard]] static std::optional<IpRange> TryParse(std::string_view text);
    [[nodiscard]] bool Contains(const IpAddress& address) const noexcept;

private:
    IpRange(IpAddress first, IpAddress last) noexcept;
    IpAddress m_first;
    IpAddress m_last;
};

} // namespace tailgate::net
