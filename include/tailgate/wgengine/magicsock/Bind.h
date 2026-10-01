#pragma once

#include <chrono>
#include <stop_token>

#include <tailgate/wgengine/magicsock/Connection.h>

namespace tailgate::wgengine::magicsock
{

// Bootstrap-worker operation, before publishing endpoints or starting packet dispatch.
// Opens the transport and waits for either synchronous or completion-based binding.
// On failure, only the connection opened by this call is closed. Other readiness is
// returned to the event loop for the node worker to dispatch after bootstrap.
[[nodiscard]] net::Endpoint Bind(Connection& connection,
                                 const types::nettype::UdpSocketOptions& options,
                                 base::EventLoop& events,
                                 base::TimeProvider& time,
                                 std::chrono::milliseconds timeout,
                                 std::stop_token cancellation = {});

} // namespace tailgate::wgengine::magicsock
