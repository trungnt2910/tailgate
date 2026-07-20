#pragma once

#include <memory>

#include "common/UwpAliases.h"

#include "app/view/MainWindowView.h"

namespace tailgate::uwp
{

class ContentDialogView;
class MainWindowController;
class NavigationController;
class NavigationPageView;

class MainWindowViewImpl final : public MainWindowView
{
public:
    MainWindowViewImpl(MainWindowController& controller,
                       NavigationController& navigationController,
                       std::unique_ptr<ContentDialogView> contentDialogView,
                       std::unique_ptr<NavigationPageView> navigationPageView);

    void Show() override;

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;

    MainWindowController& m_controller;
    NavigationController& m_navigationController;
    std::unique_ptr<ContentDialogView> m_contentDialogView;
    std::unique_ptr<NavigationPageView> m_navigationPageView;
};

} // namespace tailgate::uwp
