#pragma once

#include <optional>

#include "app/controller/HomePageController.h"

namespace tailgate::uwp::tests
{

class FakeHomePageController final : public HomePageController
{
public:
    [[nodiscard]] const HomePageState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] HomePageState& GetState() noexcept
    {
        return m_state;
    }

    void SearchText(const winrt::hstring& value) override
    {
        SearchTextArgument = value;
        m_state.SearchText(value);
    }

    std::optional<winrt::hstring> SearchTextArgument;

private:
    HomePageState m_state;
};

} // namespace tailgate::uwp::tests
