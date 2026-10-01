#pragma once

#include <chrono>
#include <stop_token>

namespace tailgate::linux_frontend::impl
{

void WaitForSocket(int descriptor,
                   short events,
                   std::chrono::seconds timeout,
                   std::stop_token cancellation);
void ThrowIfCancelled(std::stop_token cancellation);

} // namespace tailgate::linux_frontend::impl
