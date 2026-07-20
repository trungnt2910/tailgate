#pragma once
#include "tailgate/acme/AcmeClient.h"
#include <chrono>

namespace tailgate::linux_frontend
{

class LinuxAcmeHttpClient final : public acme::IHttpClient
{
public:
    [[nodiscard]] acme::HttpResponse Send(const acme::HttpRequest& request) override;
};

class LinuxAcmeWaiter final : public acme::IWaiter
{
public:
    void Wait(std::chrono::seconds duration) override;
};

} // namespace tailgate::linux_frontend
