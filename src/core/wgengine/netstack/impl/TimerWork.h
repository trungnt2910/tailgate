#pragma once

namespace tailgate::wgengine::netstack::impl
{

// Call under Runtime::Mutex(), after lwIP initialization. Empty cyclic maintenance
// must not force a hosted relay round trip just to enter the UWP receive callback.
[[nodiscard]] bool HasTimerWork() noexcept;

} // namespace tailgate::wgengine::netstack::impl
