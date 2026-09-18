#include "MbedTlsThreading.h"

#include <condition_variable>
#include <mutex>

#include <mbedtls/threading.h>

namespace tailgate::crypto::detail
{
namespace
{

template <typename T>
int Initialize(void** handle) noexcept
{
    *handle = nullptr;
    try
    {
        *handle = new T;
        return 0;
    }
    catch (...)
    {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
}

template <typename T>
void Destroy(void** handle) noexcept
{
    delete static_cast<T*>(*handle);
    *handle = nullptr;
}

int Lock(void** handle) noexcept
{
    try
    {
        static_cast<std::mutex*>(*handle)->lock();
        return 0;
    }
    catch (...)
    {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
}

int Unlock(void** handle) noexcept
{
    static_cast<std::mutex*>(*handle)->unlock();
    return 0;
}

int Signal(void** handle) noexcept
{
    static_cast<std::condition_variable*>(*handle)->notify_one();
    return 0;
}

int Broadcast(void** handle) noexcept
{
    static_cast<std::condition_variable*>(*handle)->notify_all();
    return 0;
}

int Wait(void** condition, void** mutex) noexcept
{
    std::unique_lock lock(*static_cast<std::mutex*>(*mutex), std::adopt_lock);
    try
    {
        static_cast<std::condition_variable*>(*condition)->wait(lock);
    }
    catch (...)
    {
        // The C caller retains ownership of the mutex even when waiting fails.
        (void)lock.release();
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }
    (void)lock.release();
    return 0;
}

class ThreadingRuntime final
{
public:
    ThreadingRuntime()
    {
        mbedtls_threading_set_alt(Initialize<std::mutex>,
                                  Destroy<std::mutex>,
                                  Lock,
                                  Unlock,
                                  Initialize<std::condition_variable>,
                                  Destroy<std::condition_variable>,
                                  Signal,
                                  Broadcast,
                                  Wait);
    }

    ~ThreadingRuntime()
    {
        mbedtls_threading_free_alt();
    }
};

} // namespace

void InitializeMbedTlsThreading()
{
    // Also order destruction correctly if a consumer constructs a crypto object globally.
    static const ThreadingRuntime runtime;
}

namespace
{

// Register during module initialization, before application worker threads start. The runtime
// outlives every PsaCryptoContext and is not torn down between separate PSA usage intervals.
[[maybe_unused]] const bool ThreadingInitialized = []()
{
    InitializeMbedTlsThreading();
    return true;
}();

} // namespace
} // namespace tailgate::crypto::detail
