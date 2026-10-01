#pragma once

namespace tailgate::uwp
{

// Native Core workers need WinRT initialization on each calling thread. Existing
// UI apartments remain untouched; initialization owned here lasts until thread exit.
class ThreadApartment final
{
public:
    static void Ensure();

    ThreadApartment(const ThreadApartment&) = delete;
    ThreadApartment& operator=(const ThreadApartment&) = delete;

private:
    ThreadApartment();
    ~ThreadApartment();

    bool m_initialized = false;
};

} // namespace tailgate::uwp
