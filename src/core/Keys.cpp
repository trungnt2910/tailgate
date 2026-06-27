#include "tailgate/protocol/Keys.h"

#include <iomanip>
#include <sstream>
#include <utility>

namespace tailgate::protocol
{

PublicKey::PublicKey(std::array<std::uint8_t, Size> bytes) : m_bytes(std::move(bytes))
{
}

const std::array<std::uint8_t, PublicKey::Size>& PublicKey::Bytes() const
{
    return m_bytes;
}

std::string PublicKey::ToHex() const
{
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (std::uint8_t byte : m_bytes)
    {
        stream << std::setw(2) << static_cast<int>(byte);
    }
    return stream.str();
}

} // namespace tailgate::protocol
