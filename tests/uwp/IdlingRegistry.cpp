#include "IdlingRegistry.h"

#include <algorithm>
#include <chrono>

#include "TestHost.h"

namespace tailgate::uwp::tests
{

void IdlingRegistry::Register(IIdlingResource& resource)
{
    if (std::ranges::find(m_resources, &resource) == m_resources.end())
    {
        m_resources.push_back(&resource);
    }
}

void IdlingRegistry::Deregister(IIdlingResource& resource)
{
    std::erase(m_resources, &resource);
}

void IdlingRegistry::SetTimeout(std::chrono::milliseconds timeout) noexcept
{
    m_timeout = timeout;
}

void IdlingRegistry::OnIdle() const
{
    const auto deadline = std::chrono::steady_clock::now() + m_timeout;
    while (true)
    {
        bool idle = false;
        TestHost::RunOnUiThread(
            [this, &idle]
            {
                idle = AreAllResourcesIdle();
            });
        if (idle)
        {
            return;
        }
        if (std::chrono::steady_clock::now() >= deadline)
        {
            throw IdlingResourceTimeoutError();
        }
        TestHost::WaitForIdleAsync().get();
    }
}

bool IdlingRegistry::AreAllResourcesIdle() const noexcept
{
    return std::ranges::all_of(m_resources,
                               [](const IIdlingResource* resource)
                               {
                                   return resource->IsIdle();
                               });
}

} // namespace tailgate::uwp::tests
