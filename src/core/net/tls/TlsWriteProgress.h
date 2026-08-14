#pragma once

#include <cstdint>

namespace tailgate::net::tls::detail
{

template <typename Write>
int WriteWithReadProgress(Write&& write, int wantRead, const std::uint64_t& readGeneration)
{
    int result = write();
    while (result == wantRead)
    {
        const std::uint64_t previousGeneration = readGeneration;
        result = write();
        if (result == wantRead && readGeneration == previousGeneration)
        {
            return result;
        }
    }
    return result;
}

} // namespace tailgate::net::tls::detail
