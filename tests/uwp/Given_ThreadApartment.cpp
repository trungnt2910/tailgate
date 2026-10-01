#include <exception>
#include <thread>

#include <objbase.h>

// Win32's legacy macro collides with the XAML animation interface in TestHost.
#ifdef GetCurrentTime
#undef GetCurrentTime
#endif

#include <gtest/gtest.h>
#include <winrt/base.h>

#include "common/ThreadApartment.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{

TEST(Given_ThreadApartment, When_EnsuredTwiceOnNativeWorker_Then_WorkerHasMultithreadedApartment)
{
    APTTYPE type{};
    APTTYPEQUALIFIER qualifier{};
    HRESULT result = E_FAIL;
    std::exception_ptr failure;

    std::thread worker(
        [&]
        {
            try
            {
                ThreadApartment::Ensure();
                ThreadApartment::Ensure();
                result = CoGetApartmentType(&type, &qualifier);
            }
            catch (...)
            {
                failure = std::current_exception();
            }
        });
    worker.join();

    EXPECT_EQ(failure, nullptr);
    EXPECT_EQ(result, S_OK);
    EXPECT_EQ(type, APTTYPE_MTA);
}

TEST(Given_ThreadApartment, When_CalledOnUiThread_Then_ExistingApartmentIsPreserved)
{
    APTTYPE before{};
    APTTYPE after{};
    APTTYPEQUALIFIER qualifier{};
    HRESULT beforeResult = E_FAIL;
    HRESULT afterResult = E_FAIL;

    TestHost::RunOnUiThread(
        [&]
        {
            beforeResult = CoGetApartmentType(&before, &qualifier);
            ThreadApartment::Ensure();
            afterResult = CoGetApartmentType(&after, &qualifier);
        });

    EXPECT_EQ(beforeResult, S_OK);
    EXPECT_EQ(afterResult, S_OK);
    EXPECT_EQ(after, before);
    EXPECT_TRUE(after == APTTYPE_STA || after == APTTYPE_MAINSTA);
}

} // namespace tailgate::uwp::tests
