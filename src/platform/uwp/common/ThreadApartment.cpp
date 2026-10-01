#include "ThreadApartment.h"

#include <roapi.h>

#include <winrt/base.h>

namespace tailgate::uwp
{

ThreadApartment::ThreadApartment()
{
    const auto result = RoInitialize(RO_INIT_MULTITHREADED);
    m_initialized = SUCCEEDED(result);
    if (!m_initialized && result != RPC_E_CHANGED_MODE)
    {
        winrt::check_hresult(result);
    }
}

ThreadApartment::~ThreadApartment()
{
    if (m_initialized)
    {
        RoUninitialize();
    }
}

void ThreadApartment::Ensure()
{
    thread_local ThreadApartment apartment;
}

} // namespace tailgate::uwp
