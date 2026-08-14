#pragma once

#include <tailgate/PlatformFrontend.h>

namespace tailgate
{

int RunApplication(int argc, char** argv, platform::IPlatformFrontend& frontend);

} // namespace tailgate
