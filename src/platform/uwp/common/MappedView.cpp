#include "MappedView.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace tailgate::uwp
{

void detail::MappedViewTraits::close(type value) noexcept
{
    UnmapViewOfFile(value);
}

} // namespace tailgate::uwp
