#include <tailgate/crypto/Keys.h>

#include <string>
#include <utility>

#include <boost/algorithm/hex.hpp>

namespace tailgate::crypto
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
    std::string result;
    result.reserve(m_bytes.size() * 2);
    boost::algorithm::hex_lower(m_bytes, std::back_inserter(result));
    return result;
}

} // namespace tailgate::crypto
