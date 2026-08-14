#include <tailgate/wgengine/wireguard/ReplayWindow.h>

#include <algorithm>

namespace tailgate::wgengine::wireguard
{

bool ReplayWindow::Accept(std::uint64_t counter)
{
    if (!m_initialized)
    {
        m_initialized = true;
        m_highest = counter;
        Set(counter);
        return true;
    }

    if (counter > m_highest)
    {
        const std::uint64_t advance = counter - m_highest;
        if (advance >= WindowSize)
        {
            m_bitmap.fill(0);
        }
        else
        {
            for (std::uint64_t value = m_highest + 1; value <= counter; ++value)
            {
                Clear(value);
            }
        }
        m_highest = counter;
        Set(counter);
        return true;
    }

    if (m_highest - counter >= WindowSize || IsSet(counter))
    {
        return false;
    }
    Set(counter);
    return true;
}

void ReplayWindow::Reset()
{
    m_bitmap.fill(0);
    m_highest = 0;
    m_initialized = false;
}

bool ReplayWindow::IsSet(std::uint64_t counter) const
{
    const std::size_t bit = static_cast<std::size_t>(counter % WindowSize);
    return (m_bitmap[bit / BitsPerWord] & (std::uint64_t{1} << (bit % BitsPerWord))) != 0;
}

void ReplayWindow::Set(std::uint64_t counter)
{
    const std::size_t bit = static_cast<std::size_t>(counter % WindowSize);
    m_bitmap[bit / BitsPerWord] |= std::uint64_t{1} << (bit % BitsPerWord);
}

void ReplayWindow::Clear(std::uint64_t counter)
{
    const std::size_t bit = static_cast<std::size_t>(counter % WindowSize);
    m_bitmap[bit / BitsPerWord] &= ~(std::uint64_t{1} << (bit % BitsPerWord));
}

} // namespace tailgate::wgengine::wireguard
