#pragma once

#include <concepts>
#include <cstddef>
#include <functional>
#include <utility>

#include "common/UwpAliases.h"

namespace tailgate::uwp
{

namespace detail
{

template <typename Type>
Type DefaultPropertyValue()
{
    if constexpr (std::default_initializable<Type>)
    {
        return Type{};
    }
    else
    {
        static_assert(std::constructible_from<Type, std::nullptr_t>);
        return Type{nullptr};
    }
}

} // namespace detail

using StateEventRegistration = xaml_data::INotifyPropertyChanged::PropertyChanged_revoker;

template <typename Derived>
class ObservableState : public winrt::implements<Derived, xaml_data::INotifyPropertyChanged>
{
public:
    [[nodiscard]] StateEventRegistration
    Subscribe(const xaml_data::PropertyChangedEventHandler& handler) const
    {
        const foundation::IInspectable inspectable = *this;
        const auto observable = inspectable.as<xaml_data::INotifyPropertyChanged>();
        return observable.PropertyChanged(winrt::auto_revoke, handler);
    }

    winrt::event_token PropertyChanged(const xaml_data::PropertyChangedEventHandler& handler)
    {
        return m_propertyChanged.add(handler);
    }

    void PropertyChanged(const winrt::event_token& token) noexcept
    {
        m_propertyChanged.remove(token);
    }

    template <typename Function>
    void Update(Function&& function)
    {
        struct NotificationGuard
        {
            ObservableState& State;
            bool NotificationsEnabled;

            ~NotificationGuard()
            {
                State.m_notificationsEnabled = NotificationsEnabled;
                if (NotificationsEnabled)
                {
                    State.NotifyChange();
                }
            }
        };

        const NotificationGuard guard{
            .State = *this,
            .NotificationsEnabled = std::exchange(m_notificationsEnabled, false),
        };

        if constexpr (std::invocable<Function, Derived&>)
        {
            std::invoke(std::forward<Function>(function), *static_cast<Derived*>(this));
        }
        else
        {
            static_assert(std::invocable<Function>);
            std::invoke(std::forward<Function>(function));
        }
    }

protected:
    template <typename Type, const char* Name>
    void AssignIfChanged(Type& target, Type value)
    {
        if (target == value)
        {
            return;
        }
        target = std::move(value);
        NotifyChange(winrt::to_hstring(Name));
    }

    void NotifyChange(const winrt::hstring& propertyName = {})
    {
        if (!m_notificationsEnabled)
        {
            return;
        }
        m_propertyChanged(*static_cast<Derived*>(this),
                          xaml_data::PropertyChangedEventArgs(propertyName));
    }

private:
    winrt::event<xaml_data::PropertyChangedEventHandler> m_propertyChanged;
    bool m_notificationsEnabled = true;
};

} // namespace tailgate::uwp

#define TAILGATE_PROPERTY(PascalCase, Type)                                                        \
private:                                                                                           \
    static constexpr char m_propertyName##PascalCase[] = #PascalCase;                              \
    Type m_property##PascalCase = ::tailgate::uwp::detail::DefaultPropertyValue<Type>();           \
                                                                                                   \
public:                                                                                            \
    [[nodiscard]] const Type& PascalCase() const noexcept                                          \
    {                                                                                              \
        return m_property##PascalCase;                                                             \
    }                                                                                              \
                                                                                                   \
    void PascalCase(Type value)                                                                    \
    {                                                                                              \
        AssignIfChanged<Type, m_propertyName##PascalCase>(m_property##PascalCase,                  \
                                                          std::move(value));                       \
    }
