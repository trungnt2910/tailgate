#include "common/VpnPhonebook.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.Storage.h>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

namespace tailgate::uwp
{

namespace
{

constexpr std::uint32_t MaximumPhonebookSize = 1024 * 1024;

std::optional<std::size_t> DeviceOffset(std::string_view bytes)
{
    // Reject UTF-16 or binary data; the offsets below apply to byte-oriented text.
    if (bytes.find('\0') != std::string_view::npos)
    {
        return std::nullopt;
    }
    unsigned sections = 0;
    unsigned types = 0;
    unsigned devices = 0;
    bool inTailgate = false;
    bool vpnProfile = false;
    std::optional<std::size_t> device;
    constexpr std::string_view utf8Bom = "\xef\xbb\xbf";
    for (std::size_t offset = bytes.starts_with(utf8Bom) ? utf8Bom.size() : 0;
         offset < bytes.size();)
    {
        const auto end = bytes.find('\n', offset);
        auto line = bytes.substr(offset, end == bytes.npos ? bytes.size() - offset : end - offset);
        if (line.ends_with('\r'))
        {
            line.remove_suffix(1);
        }
        if (line.starts_with('['))
        {
            inTailgate = line == "[Tailgate]";
            sections += inTailgate;
        }
        else if (inTailgate && line.starts_with("Type="))
        {
            ++types;
            vpnProfile = line == "Type=2";
        }
        else if (inTailgate && line.starts_with("DEVICE="))
        {
            ++devices;
            if (line == "DEVICE=modem" || line == "DEVICE=vpn")
            {
                device = offset + std::string_view("DEVICE=").size();
            }
        }
        if (end == bytes.npos)
        {
            break;
        }
        offset = end + 1;
    }
    return sections == 1 && types == 1 && devices == 1 && vpnProfile ? device : std::nullopt;
}

} // namespace

bool VpnPhonebook::SetVpnDeviceType(std::string& bytes)
{
    const auto offset = DeviceOffset(bytes);
    if (!offset || !std::string_view(bytes).substr(*offset).starts_with("modem"))
    {
        return false;
    }
    bytes.replace(*offset, std::string_view("modem").size(), "vpn");
    return true;
}

winrt::Windows::Foundation::IAsyncAction
VpnPhonebook::RepairAsync(winrt::Windows::Storage::StorageFolder folder)
{
    using namespace winrt::Windows::Storage;
    using namespace winrt::Windows::Storage::Streams;
    const base::Logger logger("uwp-vpn-phonebook");
    try
    {
        const auto file = co_await folder.GetFileAsync(L"rasphone.pbk");
        auto transaction = co_await file.OpenTransactedWriteAsync();
        auto stream = transaction.Stream();
        if (stream.Size() > MaximumPhonebookSize)
        {
            logger.LogWarning("skipped oversized phonebook");
            co_return;
        }
        DataReader reader(stream.GetInputStreamAt(0));
        const auto size = static_cast<std::uint32_t>(stream.Size());
        const auto loaded = co_await reader.LoadAsync(size);
        if (loaded != size)
        {
            logger.LogWarning("skipped incomplete phonebook read");
            co_return;
        }
        std::string bytes(size, '\0');
        reader.ReadBytes(winrt::array_view(reinterpret_cast<std::uint8_t*>(bytes.data()), size));
        reader.DetachStream();
        if (!SetVpnDeviceType(bytes))
        {
            co_return;
        }
        DataWriter writer(stream.GetOutputStreamAt(0));
        writer.WriteBytes(
            winrt::array_view(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()));
        const auto stored = co_await writer.StoreAsync();
        const bool flushed = co_await writer.FlushAsync();
        if (stored != bytes.size() || !flushed)
        {
            logger.LogWarning("incomplete write; discarding transaction");
            co_return;
        }
        writer.DetachStream();
        stream.Size(bytes.size());
        co_await transaction.CommitAsync();
        logger.LogInfo("corrected VPN profile device type from modem to vpn");
    }
    catch (const winrt::hresult_error& error)
    {
        // Failure to repair Settings classification must not fail a working VPN.
        logger.LogWarning("phonebook repair failed hresult={}", error.code());
    }
    co_return;
}

} // namespace tailgate::uwp
