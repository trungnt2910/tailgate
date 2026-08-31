#pragma once

#include <optional>
#include <utility>

namespace tailgate::linux_frontend::impl::detail
{

template <typename Value, typename Attempt, typename Wait>
std::optional<Value> CompleteSocketIo(bool nonBlocking, Attempt&& attempt, Wait&& wait)
{
    std::optional<Value> result = std::forward<Attempt>(attempt)();
    while (!result && !nonBlocking)
    {
        std::forward<Wait>(wait)();
        result = std::forward<Attempt>(attempt)();
    }
    return result;
}

} // namespace tailgate::linux_frontend::impl::detail
