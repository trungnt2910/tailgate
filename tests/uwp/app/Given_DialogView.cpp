#include <algorithm>
#include <cmath>
#include <limits>

#include <gtest/gtest.h>

#include "app/view/DialogView.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

class ExposedDialogView final : public DialogView
{
public:
    ExposedDialogView()
    {
        Initialize();
    }

    [[nodiscard]] controls::ContentDialog Dialog() const override
    {
        return m_dialog;
    }

private:
    void Render() override
    {
        m_dialog = CreateContentDialog();
    }

    void OnStateChange(const std::string&) override
    {
    }

    controls::ContentDialog m_dialog{nullptr};
};

} // namespace

TEST(Given_DialogView, When_Measured_Then_DialogWidthIsConstrainedToWindow)
{
    double minimumWidth = std::numeric_limits<double>::quiet_NaN();
    double maximumWidth = std::numeric_limits<double>::quiet_NaN();

    TestHost::RunOnUiThread(
        [&minimumWidth, &maximumWidth]
        {
            const ExposedDialogView subject;
            const auto dialog = subject.Dialog();
            foundation::Size available;
            available.Width = 1024;
            available.Height = 768;
            dialog.Measure(available);
            minimumWidth = winrt::unbox_value<double>(
                dialog.Resources().Lookup(winrt::box_value(L"ContentDialogMinWidth")));
            maximumWidth = winrt::unbox_value<double>(
                dialog.Resources().Lookup(winrt::box_value(L"ContentDialogMaxWidth")));
        });

    EXPECT_GT(minimumWidth, 0);
    EXPECT_DOUBLE_EQ(minimumWidth, maximumWidth);
    EXPECT_LE(maximumWidth, TestHost::StandardViewportWidth);
}

TEST(Given_DialogView, When_MeasuredRepeatedly_Then_DialogWidthRemainsStable)
{
    double firstWidth = std::numeric_limits<double>::quiet_NaN();
    double secondWidth = std::numeric_limits<double>::quiet_NaN();

    TestHost::RunOnUiThread(
        [&firstWidth, &secondWidth]
        {
            const ExposedDialogView subject;
            const auto dialog = subject.Dialog();
            foundation::Size available;
            available.Width = 1024;
            available.Height = 768;
            dialog.Measure(available);
            firstWidth = winrt::unbox_value<double>(
                dialog.Resources().Lookup(winrt::box_value(L"ContentDialogMaxWidth")));
            dialog.Measure(available);
            secondWidth = winrt::unbox_value<double>(
                dialog.Resources().Lookup(winrt::box_value(L"ContentDialogMaxWidth")));
        });

    EXPECT_TRUE(std::isfinite(firstWidth));
    EXPECT_DOUBLE_EQ(firstWidth, secondWidth);
}

} // namespace tailgate::uwp::tests
