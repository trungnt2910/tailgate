#pragma once

#include "app/controller/HomePageController.h"
#include "app/model/HomePageState.h"

namespace tailgate::uwp
{

class HomePageControllerImpl final : public HomePageController
{
public:
    [[nodiscard]] const HomePageState& GetState() const noexcept override;
    void SearchText(const winrt::hstring& value) override;

private:
    HomePageState m_state;
};

} // namespace tailgate::uwp
