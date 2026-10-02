#include "TcpSocketBinder.h"

#include <cerrno>
#include <system_error>

#include <sys/socket.h>

namespace tailgate::linux_frontend::impl
{

void TcpSocketBinder::BindToInterface(int descriptor, const std::string& interfaceName)
{
    if (setsockopt(descriptor,
                   SOL_SOCKET,
                   SO_BINDTODEVICE,
                   interfaceName.c_str(),
                   interfaceName.size() + 1) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
}

} // namespace tailgate::linux_frontend::impl
