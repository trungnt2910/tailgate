#pragma once

#include <string>

#include "UniqueFd.h"

namespace tailgate::linux_frontend
{

class PacketDescriptorProvider final
{
public:
    void Borrow(int descriptor) noexcept;
    [[nodiscard]] UniqueFd Open(const std::string& name) const;

private:
    int m_borrowedDescriptor = -1;
};

} // namespace tailgate::linux_frontend
