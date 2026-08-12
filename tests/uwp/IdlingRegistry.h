#pragma once

#include <chrono>
#include <exception>
#include <vector>

namespace tailgate::uwp::tests
{

class IIdlingResource
{
public:
    virtual ~IIdlingResource() = default;

    [[nodiscard]] virtual bool IsIdle() const noexcept = 0;
};

class IdlingResourceTimeoutError final : public std::exception
{
};

class IdlingRegistry final
{
public:
    inline static constexpr std::chrono::seconds DefaultTimeout{5};

    void Register(IIdlingResource& resource);
    void Deregister(IIdlingResource& resource);
    void SetTimeout(std::chrono::milliseconds timeout) noexcept;

    void OnIdle() const;

private:
    [[nodiscard]] bool AreAllResourcesIdle() const noexcept;

    std::vector<IIdlingResource*> m_resources;
    std::chrono::milliseconds m_timeout = DefaultTimeout;
};

} // namespace tailgate::uwp::tests
