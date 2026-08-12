#pragma once

#include "common/UwpAliases.h"

#include "app/view/View.h"

namespace tailgate::uwp
{

class DialogView : public View
{
public:
    virtual ~DialogView() = default;

    [[nodiscard]] virtual controls::ContentDialog Dialog() const = 0;

    virtual void OnOpening() noexcept
    {
    }

    virtual void OnClosed(controls::ContentDialogResult)
    {
    }

protected:
    [[nodiscard]] static controls::ContentDialog CreateContentDialog();
};

} // namespace tailgate::uwp
