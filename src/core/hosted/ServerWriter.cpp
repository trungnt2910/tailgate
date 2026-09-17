#include "tailgate/hosted/ServerWriter.h"

namespace tailgate::hosted
{

ServerWriter::~ServerWriter() = default;

const char* ServerWriterOpenError::what() const noexcept
{
    return "hosted writer packet source could not be opened";
}

} // namespace tailgate::hosted
