#pragma once

#include <string>
#include <utility>
#include <vector>

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class View
{
public:
    virtual ~View() = default;

    View(const View&) = delete;
    View& operator=(const View&) = delete;

protected:
    View() = default;

    void Initialize();

    template <typename State>
    void Subscribe(const State& state, std::string stateName = "")
    {
        m_stateRegistrations.push_back(state.Subscribe(
            [this, stateName = std::move(stateName)](const auto&, const auto&)
            {
                OnStateChange(stateName);
            }));
    }

private:
    virtual void Render() = 0;
    virtual void OnStateChange(const std::string& stateName) = 0;

    std::vector<StateEventRegistration> m_stateRegistrations;
};

} // namespace tailgate::uwp
