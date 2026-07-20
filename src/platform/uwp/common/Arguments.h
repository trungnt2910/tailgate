#pragma once

#include <string>
#include <vector>

#include <winrt/Windows.Foundation.h>

namespace tailgate::uwp
{

class Arguments final
{
public:
    Arguments() = delete;

    // The URI host becomes argv[0], query keys become --flags, and the special "--" key carries
    // positional arguments.
    [[nodiscard]] static std::vector<std::string>
    FromUri(const winrt::Windows::Foundation::Uri& uri);
};

} // namespace tailgate::uwp
