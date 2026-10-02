#pragma once

#include <string>

namespace tailgate::linux_frontend::impl
{

class TcpSocketBinder
{
public:
    virtual ~TcpSocketBinder() = default;

    virtual void BindToInterface(int descriptor, const std::string& interfaceName);
};

} // namespace tailgate::linux_frontend::impl
