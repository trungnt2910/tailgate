#pragma once

#include <chrono>

#include <tailgate/serve/acme/Client.h>

namespace tailgate::linux_frontend
{

class LinuxAcmeHttpClient final : public tailgate::serve::acme::IHttpClient
{
public:
    [[nodiscard]] tailgate::serve::acme::HttpResponse
    Send(const tailgate::serve::acme::HttpRequest& request) override;
};

class LinuxAcmeWaiter final : public tailgate::serve::acme::IWaiter
{
public:
    void Wait(std::chrono::seconds duration) override;
};

} // namespace tailgate::linux_frontend
