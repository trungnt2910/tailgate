#include "RandomImpl.h"

#include <sodium.h>

namespace tailgate::crypto::impl
{

void RandomImpl::Fill(std::span<std::uint8_t> output)
{
    randombytes_buf(output.data(), output.size());
}

} // namespace tailgate::crypto::impl
