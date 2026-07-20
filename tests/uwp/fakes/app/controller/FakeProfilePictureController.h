#pragma once

#include <cstddef>

#include "app/controller/ProfilePictureController.h"

namespace tailgate::uwp::tests
{

class FakeProfilePictureController final : public ProfilePictureController
{
public:
    [[nodiscard]] const ProfilePictureState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] ProfilePictureState& GetState() noexcept
    {
        return m_state;
    }

    void Load() override
    {
        ++LoadCount;
    }

    void Clear() override
    {
        ++ClearCount;
    }

    std::size_t LoadCount = 0;
    std::size_t ClearCount = 0;

private:
    ProfilePictureState m_state;
};

} // namespace tailgate::uwp::tests
