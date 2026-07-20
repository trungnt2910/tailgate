#pragma once

#include <tailgate/cli/Arguments.h>

namespace tailgate::uwp
{

class MainWindowController
{
public:
    virtual ~MainWindowController() = default;

    virtual void Activate() = 0;
    virtual void SetArguments(const tailgate::cli::Arguments& arguments) = 0;
};

} // namespace tailgate::uwp
