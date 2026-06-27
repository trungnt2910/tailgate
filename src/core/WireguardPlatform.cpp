extern "C"
{
#include "wireguard-platform.h"
}

#include <sodium.h>

#include <chrono>
#include <cstddef>
#include <cstdint>

extern "C"
{

    std::uint32_t wireguard_sys_now()
    {
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        return static_cast<std::uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
    }

    void wireguard_random_bytes(void* bytes, std::size_t size)
    {
        randombytes_buf(bytes, size);
    }

    void wireguard_tai64n_now(std::uint8_t* output)
    {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now);
        const auto nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now - seconds);
        const std::uint64_t taiSeconds =
            static_cast<std::uint64_t>(seconds.count()) + 0x400000000000000aULL;
        const std::uint32_t nanos = static_cast<std::uint32_t>(nanoseconds.count());

        for (int index = 0; index < 8; ++index)
        {
            output[index] = static_cast<std::uint8_t>(taiSeconds >> ((7 - index) * 8));
        }
        for (int index = 0; index < 4; ++index)
        {
            output[8 + index] = static_cast<std::uint8_t>(nanos >> ((3 - index) * 8));
        }
    }

    bool wireguard_is_under_load()
    {
        return false;
    }

} // extern "C"
