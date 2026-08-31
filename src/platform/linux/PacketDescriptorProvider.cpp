#include "PacketDescriptorProvider.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{

void PacketDescriptorProvider::Borrow(int descriptor) noexcept
{
    m_borrowedDescriptor = descriptor;
}

UniqueFd PacketDescriptorProvider::Open(const std::string& name) const
{
    if (m_borrowedDescriptor >= 0)
    {
        const int descriptor = dup(m_borrowedDescriptor);
        if (descriptor < 0)
        {
            throw std::system_error(errno, std::generic_category());
        }
        return UniqueFd(descriptor);
    }

    UniqueFd descriptor(open("/dev/net/tun", O_RDWR | O_NONBLOCK));
    if (descriptor.Fd < 0)
    {
        throw std::runtime_error("failed to open /dev/net/tun: " +
                                 std::string(std::strerror(errno)));
    }
    ifreq request{};
    request.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (ioctl(descriptor.Fd, TUNSETIFF, &request) != 0)
    {
        throw std::runtime_error("TUNSETIFF failed: " + std::string(std::strerror(errno)));
    }
    return descriptor;
}

} // namespace tailgate::linux_frontend
