#include <memory>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "app/ui/AppResources.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_AppResources : public testing::Test
{
protected:
    void SetUp() override
    {
        TestHost::RunOnUiThread(
            [this]
            {
                auto injector = di::make_injector();
                m_subject = injector.create<std::unique_ptr<AppResources>>();
            });
    }

    std::unique_ptr<AppResources> m_subject;
};

TEST_F(Given_AppResources, When_LookingUpSurfaceBrush_Then_ResourceIsAvailable)
{
    media::Brush brush{nullptr};

    TestHost::RunOnUiThread(
        [this, &brush]
        {
            brush = m_subject->Brush(AppBrush::Surface);
        });

    EXPECT_TRUE(brush);
}

TEST_F(Given_AppResources, When_LookingUpScalarResources_Then_TypedValuesAreAvailable)
{
    double chartWidth = 0.0;
    std::int32_t gridLineCount = 0;
    xaml::Thickness zero;
    text::FontWeight strong;

    TestHost::RunOnUiThread(
        [this, &chartWidth, &gridLineCount, &zero, &strong]
        {
            chartWidth = m_subject->Double(AppDouble::ChartWidth);
            gridLineCount = m_subject->Integer(AppInteger::ChartGridLineCount);
            zero = m_subject->Thickness(AppThickness::Zero);
            strong = m_subject->FontWeight(AppFontWeight::Strong);
        });

    EXPECT_GT(chartWidth, 0.0);
    EXPECT_GT(gridLineCount, 0);
    EXPECT_EQ(zero.Left, 0.0);
    EXPECT_EQ(zero.Top, 0.0);
    EXPECT_GT(strong.Weight, 0U);
}

TEST_F(Given_AppResources, When_LookingUpXamlResources_Then_ObjectsAreAvailable)
{
    xaml::DataTemplate dataTemplate{nullptr};
    controls::ItemsPanelTemplate itemsPanel{nullptr};
    xaml::Style style{nullptr};

    TestHost::RunOnUiThread(
        [this, &dataTemplate, &itemsPanel, &style]
        {
            dataTemplate = m_subject->DataTemplate(AppDataTemplate::DeviceGroupHeader);
            itemsPanel = m_subject->ItemsPanelTemplate(AppItemsPanelTemplate::StickyDeviceItems);
            style = m_subject->Style(AppStyle::Page);
        });

    EXPECT_TRUE(dataTemplate);
    EXPECT_TRUE(itemsPanel);
    EXPECT_TRUE(style);
}

TEST_F(Given_AppResources, When_ControlResourcesAreApplied_Then_ButtonReceivesOverrides)
{
    controls::Button button{nullptr};
    std::uint32_t resourceCount = 0;

    TestHost::RunOnUiThread(
        [this, &button, &resourceCount]
        {
            button = controls::Button();
            m_subject->Apply(button, AppControlResources::PrimaryButton);
            resourceCount = button.Resources().Size();
        });

    EXPECT_TRUE(button);
    EXPECT_GT(resourceCount, 0U);
}

} // namespace
} // namespace tailgate::uwp::tests
