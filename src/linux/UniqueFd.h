#pragma once

#include <unistd.h>

namespace tailgate::linux_frontend
{

class UniqueFd
{
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : Fd(fd)
    {
    }
    ~UniqueFd()
    {
        if (Fd >= 0)
        {
            close(Fd);
        }
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept : Fd(other.Release())
    {
    }
    UniqueFd& operator=(UniqueFd&& other) noexcept
    {
        if (this != &other)
        {
            Reset(other.Release());
        }
        return *this;
    }

    void Reset(int fd = -1)
    {
        if (Fd >= 0)
        {
            close(Fd);
        }
        Fd = fd;
    }

    [[nodiscard]] int Release()
    {
        const int result = Fd;
        Fd = -1;
        return result;
    }

    int Fd = -1;
};

} // namespace tailgate::linux_frontend
