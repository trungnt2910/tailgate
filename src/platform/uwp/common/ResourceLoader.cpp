#include "common/ResourceLoader.h"

namespace tailgate::uwp
{

winrt::hstring ResourceLoader::Get(UwpError::Code error) const
{
    return Get(UwpError::Resource(error));
}

} // namespace tailgate::uwp
