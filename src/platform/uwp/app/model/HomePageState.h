#pragma once

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class HomePageState final : public ObservableState<HomePageState>
{
    TAILGATE_PROPERTY(SearchText, winrt::hstring);
};

} // namespace tailgate::uwp
