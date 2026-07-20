#include "app/controller/impl/ProfilePictureControllerImpl.h"

#include <filesystem>

#include <winrt/Windows.Storage.h>
#include <winrt/Windows.UI.Xaml.Media.Imaging.h>
#include <winrt/Windows.Web.Http.h>

#include "app/controller/SettingsController.h"

namespace tailgate::uwp
{

namespace http = winrt::Windows::Web::Http;
namespace imaging = winrt::Windows::UI::Xaml::Media::Imaging;
namespace storage = winrt::Windows::Storage;

namespace
{

constexpr wchar_t ProfilePictureFileName[] = L"profile-pic.img";

} // namespace

ProfilePictureControllerImpl::ProfilePictureControllerImpl(SettingsController& settingsController)
    : m_settingsController(settingsController)
{
}

const ProfilePictureState& ProfilePictureControllerImpl::GetState() const noexcept
{
    return m_state;
}

void ProfilePictureControllerImpl::Load()
{
    if (!m_loading)
    {
        (void)LoadAsync();
    }
}

void ProfilePictureControllerImpl::Clear()
{
    m_applied = false;
    m_state.Image(nullptr);
}

FireAndForget ProfilePictureControllerImpl::LoadAsync()
{
    m_loading = true;
    try
    {
        const auto folder = storage::ApplicationData::Current().LocalFolder();
        const std::filesystem::path cachePath =
            std::filesystem::path(folder.Path().c_str()) / ProfilePictureFileName;
        const SettingsState& settings = m_settingsController.GetState();
        if (m_applied && settings.CachedProfilePictureUrl() == settings.ProfilePicUrl())
        {
            m_loading = false;
            co_return;
        }
        if (settings.CachedProfilePictureUrl() != settings.ProfilePicUrl())
        {
            std::error_code error;
            (void)std::filesystem::remove(cachePath, error);
            m_settingsController.ClearCachedProfilePictureUrl();
            Clear();
        }
        if (settings.ProfilePicUrl().empty())
        {
            m_loading = false;
            co_return;
        }
        if (!std::filesystem::exists(cachePath))
        {
            http::HttpClient client;
            const auto buffer =
                co_await client.GetBufferAsync(foundation::Uri(settings.ProfilePicUrl()));
            const auto file = co_await folder.CreateFileAsync(
                ProfilePictureFileName, storage::CreationCollisionOption::ReplaceExisting);
            co_await storage::FileIO::WriteBufferAsync(file, buffer);
        }
        const auto file = co_await folder.GetFileAsync(ProfilePictureFileName);
        const auto stream = co_await file.OpenAsync(storage::FileAccessMode::Read);
        imaging::BitmapImage image;
        co_await image.SetSourceAsync(stream);
        m_settingsController.SetCachedProfilePictureUrl(settings.ProfilePicUrl());
        m_state.Image(image);
        m_applied = true;
        m_loading = false;
        co_return;
    }
    catch (const winrt::hresult_error& error)
    {
        const auto folder = storage::ApplicationData::Current().LocalFolder();
        std::error_code removalError;
        (void)std::filesystem::remove(
            std::filesystem::path(folder.Path().c_str()) / ProfilePictureFileName, removalError);
        m_settingsController.ClearCachedProfilePictureUrl();
        m_logger.LogWarning("load failed: {}", error.message());
    }
    m_loading = false;
}

} // namespace tailgate::uwp
