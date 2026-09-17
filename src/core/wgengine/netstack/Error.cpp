#include "tailgate/wgengine/netstack/Error.h"

namespace tailgate::wgengine::netstack
{

Exception::Exception(Error error) noexcept : m_error(error)
{
}

Error Exception::Reason() const noexcept
{
    return m_error;
}

const char* Exception::what() const noexcept
{
    return "TCP stack operation failed";
}

} // namespace tailgate::wgengine::netstack
