#include <array>
#include <cstddef>
#include <latch>
#include <thread>

#include <gtest/gtest.h>
#include <mbedtls/threading.h>

namespace
{

struct Mutex final
{
    Mutex()
    {
        mbedtls_mutex_init(&Value);
    }

    ~Mutex()
    {
        mbedtls_mutex_free(&Value);
    }

    mbedtls_threading_mutex_t Value{};
};

struct Condition final
{
    Condition()
    {
        Status = mbedtls_condition_variable_init(&Value);
    }

    ~Condition()
    {
        mbedtls_condition_variable_free(&Value);
    }

    mbedtls_threading_condition_variable_t Value{};
    int Status = 0;
};

struct Wakeup final
{
    std::size_t Waiters;
    int (*Notify)(mbedtls_threading_condition_variable_t*);
};

class Given_MbedTlsThreadingWakeup : public testing::TestWithParam<Wakeup>
{
};

} // namespace

TEST(Given_MbedTlsThreading, When_MutexWasNotInitialized_Then_LockingReportsFailure)
{
    mbedtls_threading_mutex_t mutex{};

    const int result = mbedtls_mutex_lock(&mutex);
    mbedtls_mutex_free(&mutex);

    EXPECT_EQ(result, MBEDTLS_ERR_THREADING_USAGE_ERROR);
}

TEST_P(Given_MbedTlsThreadingWakeup, When_Notified_Then_WaitersReturnHoldingTheMutex)
{
    const Wakeup wakeup = GetParam();
    Mutex mutex;
    Condition condition;
    ASSERT_EQ(condition.Status, 0);
    ASSERT_EQ(mbedtls_mutex_lock(&mutex.Value), 0);
    ASSERT_EQ(mbedtls_mutex_unlock(&mutex.Value), 0);
    constexpr std::size_t MaximumWaiters = 2;
    std::array<int, MaximumWaiters> results{};
    std::array<std::jthread, MaximumWaiters> workers;
    std::latch entered(static_cast<std::ptrdiff_t>(wakeup.Waiters));
    bool ready = false;
    std::size_t completed = 0;

    for (std::size_t index = 0; index < wakeup.Waiters; ++index)
    {
        workers[index] = std::jthread(
            [&, index]()
            {
                results[index] = mbedtls_mutex_lock(&mutex.Value);
                entered.count_down();
                if (results[index] != 0)
                {
                    return;
                }
                while (!ready && results[index] == 0)
                {
                    results[index] =
                        mbedtls_condition_variable_wait(&condition.Value, &mutex.Value);
                }
                ++completed;
                results[index] |= mbedtls_mutex_unlock(&mutex.Value);
            });
    }
    entered.wait();
    const int locked = mbedtls_mutex_lock(&mutex.Value);
    ready = true;
    const int notified = wakeup.Notify(&condition.Value);
    const int unlocked = mbedtls_mutex_unlock(&mutex.Value);
    for (std::size_t index = 0; index < wakeup.Waiters; ++index)
    {
        workers[index].join();
    }

    EXPECT_EQ(locked, 0);
    EXPECT_EQ(notified, 0);
    EXPECT_EQ(unlocked, 0);
    EXPECT_EQ(results, (std::array<int, MaximumWaiters>{0, 0}));
    EXPECT_EQ(completed, wakeup.Waiters);
}

INSTANTIATE_TEST_SUITE_P(
    Notifications,
    Given_MbedTlsThreadingWakeup,
    testing::Values(Wakeup{.Waiters = 1, .Notify = mbedtls_condition_variable_signal},
                    Wakeup{.Waiters = 2, .Notify = mbedtls_condition_variable_broadcast}));
