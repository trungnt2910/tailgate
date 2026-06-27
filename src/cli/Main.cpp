#include "tailgate/Application.h"
#include "tailgate/PlatformFrontend.h"

int main(int argc, char** argv)
{
    std::unique_ptr<tailgate::platform::IPlatformFrontend> frontend =
        tailgate::platform::CreateFrontend();
    return tailgate::RunApplication(argc, argv, *frontend);
}
