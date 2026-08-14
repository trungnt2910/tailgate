extern "C"
{
#include "wireguard-platform.h"
}

#include <chrono>
#include <cstddef>
#include <cstdint>

#include <sodium.h>

namespace
{

constexpr std::uint64_t Tai64UnixEpochOffset = 0x400000000000000aULL;
constexpr int Tai64SecondsSize = 8;
constexpr int Tai64NanosecondsSize = 4;
constexpr int BitsPerByte = 8;

} // namespace

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
            static_cast<std::uint64_t>(seconds.count()) + Tai64UnixEpochOffset;
        const std::uint32_t nanos = static_cast<std::uint32_t>(nanoseconds.count());

        for (int index = 0; index < Tai64SecondsSize; ++index)
        {
            output[index] = static_cast<std::uint8_t>(
                taiSeconds >> ((Tai64SecondsSize - 1 - index) * BitsPerByte));
        }
        for (int index = 0; index < Tai64NanosecondsSize; ++index)
        {
            output[Tai64SecondsSize + index] = static_cast<std::uint8_t>(
                nanos >> ((Tai64NanosecondsSize - 1 - index) * BitsPerByte));
        }
    }

    bool wireguard_is_under_load()
    {
        return false;
    }

} // extern "C"
