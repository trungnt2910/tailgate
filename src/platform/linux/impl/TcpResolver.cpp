#include "TcpResolver.h"

#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <system_error>

#include <ares.h>

#include <tailgate/base/Logger.h>

#include "CancellableWait.h"

namespace tailgate::linux_frontend::impl
{
namespace
{

class ResolverLibrary final
{
public:
    ResolverLibrary()
    {
        if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
        {
            throw std::system_error(std::make_error_code(std::errc::not_enough_memory));
        }
    }

    ~ResolverLibrary()
    {
        ares_library_cleanup();
    }
};

struct Resolution
{
    std::mutex Mutex;
    std::condition_variable_any Changed;
    bool Done = false;
    int Status = ARES_SUCCESS;
    std::unique_ptr<ares_addrinfo, decltype(&ares_freeaddrinfo)> Addresses{nullptr,
                                                                           ares_freeaddrinfo};
};

void Resolved(void* context, int status, int, ares_addrinfo* addresses)
{
    auto& result = *static_cast<Resolution*>(context);
    {
        std::lock_guard lock(result.Mutex);
        result.Status = status;
        result.Addresses.reset(addresses);
        result.Done = true;
    }
    result.Changed.notify_all();
}

} // namespace

std::vector<TcpAddress> TcpResolver::Resolve(const std::string& host,
                                             const std::string& service,
                                             std::chrono::seconds timeout,
                                             std::stop_token cancellation)
{
    ThrowIfCancelled(cancellation);
    static ResolverLibrary library;
    Resolution result;
    ares_options options{};
    options.evsys = ARES_EVSYS_DEFAULT;
    ares_channel_t* raw = nullptr;
    if (ares_init_options(&raw, &options, ARES_OPT_EVENT_THREAD) != ARES_SUCCESS)
    {
        throw std::system_error(std::make_error_code(std::errc::io_error));
    }
    // Destroying the channel cancels outstanding requests and joins its event thread
    // before the callback's borrowed result goes out of scope.
    const std::unique_ptr<ares_channel_t, decltype(&ares_destroy)> channel(raw, ares_destroy);
    // DNS follows host routing so a configured loopback resolver remains reachable.
    // The destination TCP socket selects its interface independently after resolution.
    ares_addrinfo_hints hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    ares_getaddrinfo(channel.get(), host.c_str(), service.c_str(), &hints, Resolved, &result);
    std::unique_lock lock(result.Mutex);
    const bool done = result.Changed.wait_for(lock,
                                              cancellation,
                                              timeout,
                                              [&]()
                                              {
                                                  return result.Done;
                                              });
    // Do not hold the result lock while channel destruction waits for its callback.
    lock.unlock();
    ThrowIfCancelled(cancellation);
    if (!done)
    {
        throw std::system_error(std::make_error_code(std::errc::timed_out));
    }
    if (result.Status != ARES_SUCCESS || !result.Addresses)
    {
        tailgate::base::Logger("resolver")
            .LogWarning("lookup failed host={} status={}", host, ares_strerror(result.Status));
        throw std::system_error(std::make_error_code(std::errc::host_unreachable));
    }
    std::vector<TcpAddress> addresses;
    for (auto* node = result.Addresses->nodes; node != nullptr; node = node->ai_next)
    {
        TcpAddress address;
        address.Length = node->ai_addrlen;
        address.Family = node->ai_family;
        address.Protocol = node->ai_protocol;
        if (address.Length <= sizeof(address.Address))
        {
            std::memcpy(&address.Address, node->ai_addr, address.Length);
            addresses.push_back(address);
        }
    }
    return addresses;
}

} // namespace tailgate::linux_frontend::impl
