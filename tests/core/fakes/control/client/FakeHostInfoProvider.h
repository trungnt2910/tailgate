#pragma once

#include <cstddef>

#include <tailgate/control/client/HostInfoProvider.h>

namespace tailgate::tests::fakes
{

class FakeHostInfoProvider final : public tailgate::control::client::HostInfoProvider
{
public:
    FakeHostInfoProvider() : Host("device.example.ts.net", "test", "1", "test-architecture")
    {
        Host.SetClientMetadata("Tailgate Test", "fake-frontend-log-id", "fake-backend-log-id");
    }

    [[nodiscard]] tailgate::control::client::HostInfo GetHostInfo() override
    {
        ++Calls;
        return Host;
    }

    tailgate::control::client::HostInfo Host;
    std::size_t Calls = 0;
};

} // namespace tailgate::tests::fakes
