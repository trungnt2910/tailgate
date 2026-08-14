#include "app/view/impl/ContentDialogViewImpl.h"

#include <string>
#include <utility>

#include "app/controller/ContentDialogController.h"
#include "app/view/DialogView.h"
#include "app/view/NodeAuthorizationDialogView.h"
#include "app/view/PingDialogView.h"
#include "app/view/SignInDialogView.h"

namespace tailgate::uwp
{
namespace
{

void Observe(const foundation::IAsyncAction& operation, tailgate::base::Logger logger)
{
    operation.Completed(
        [logger = std::move(logger)](const foundation::IAsyncAction& completed,
                                     foundation::AsyncStatus)
        {
            try
            {
                completed.GetResults();
            }
            catch (const winrt::hresult_error& error)
            {
                logger.LogError("dialog presentation failed: {}", error.message());
            }
        });
}

} // namespace

ContentDialogViewImpl::ContentDialogViewImpl(
    ContentDialogController& controller,
    std::unique_ptr<NodeAuthorizationDialogView> nodeAuthorizationDialog,
    std::unique_ptr<PingDialogView> pingDialog,
    std::unique_ptr<SignInDialogView> signInDialog)
    : m_controller(controller),
      m_nodeAuthorizationDialog(std::move(nodeAuthorizationDialog)),
      m_pingDialog(std::move(pingDialog)),
      m_signInDialog(std::move(signInDialog))
{
    Subscribe(m_controller.GetState(), "dialog");
    Initialize();
}

void ContentDialogViewImpl::Render()
{
}

DialogView& ContentDialogViewImpl::View(ContentDialogControllerState state) const
{
    switch (state)
    {
    case ContentDialogControllerState::SignIn:
        return *m_signInDialog;
    case ContentDialogControllerState::NodeAuthorization:
        return *m_nodeAuthorizationDialog;
    case ContentDialogControllerState::Ping:
        return *m_pingDialog;
    case ContentDialogControllerState::None:
        break;
    }
    throw winrt::hresult_invalid_argument();
}

foundation::IAsyncAction ContentDialogViewImpl::PresentAsync(DialogView& view,
                                                             ContentDialogControllerState state,
                                                             std::uint64_t generation)
{
    controls::ContentDialogResult result = controls::ContentDialogResult::None;
    view.OnOpening();
    try
    {
        result = co_await view.Dialog().ShowAsync();
    }
    catch (...)
    {
        if (m_view == &view && m_generation == generation)
        {
            m_view = nullptr;
            m_dialog = nullptr;
            m_state = ContentDialogControllerState::None;
            m_generation = 0;
            m_hiding = false;
        }
        const ContentDialogState& desired = m_controller.GetState();
        const bool supersededBySameDialog =
            desired.Current() == state && m_desiredGeneration != generation;
        if (!supersededBySameDialog)
        {
            view.OnClosed(controls::ContentDialogResult::None);
        }
        if (desired.Current() == state && m_desiredGeneration == generation)
        {
            m_controller.HideDialog(state);
        }
        UpdateDialog();
        throw;
    }

    if (m_view == &view && m_generation == generation)
    {
        m_view = nullptr;
        m_dialog = nullptr;
        m_state = ContentDialogControllerState::None;
        m_generation = 0;
        m_hiding = false;
    }
    const ContentDialogState& desired = m_controller.GetState();
    const bool supersededBySameDialog =
        desired.Current() == state && m_desiredGeneration != generation;
    if (!supersededBySameDialog)
    {
        view.OnClosed(result);
    }
    if (desired.Current() == state && m_desiredGeneration == generation)
    {
        m_controller.HideDialog(state);
    }
    UpdateDialog();
}

void ContentDialogViewImpl::OnStateChange(const std::string&)
{
    ++m_desiredGeneration;
    UpdateDialog();
}

void ContentDialogViewImpl::UpdateDialog()
{
    const ContentDialogControllerState desired = m_controller.GetState().Current();
    if (m_dialog)
    {
        if ((m_state != desired || m_generation != m_desiredGeneration) && !m_hiding)
        {
            m_hiding = true;
            m_dialog.Hide();
        }
        return;
    }
    if (desired == ContentDialogControllerState::None)
    {
        return;
    }

    m_state = desired;
    m_generation = m_desiredGeneration;
    m_view = &View(desired);
    m_dialog = m_view->Dialog();
    Observe(PresentAsync(*m_view, m_state, m_generation), m_logger);
}

} // namespace tailgate::uwp
