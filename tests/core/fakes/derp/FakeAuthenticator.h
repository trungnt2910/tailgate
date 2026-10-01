#pragma once

#include <functional>
#include <optional>

#include <tailgate/derp/Client.h>

namespace tailgate::tests::fakes::derp
{

class FakeAuthenticator final : public tailgate::derp::Authenticator
{
public:
    std::vector<std::uint8_t> Authenticate(const tailgate::derp::DerpClient::Key& key,
                                           std::stop_token cancellation) override
    {
        ServerKey = key;
        if (OnAuthenticate)
        {
            return OnAuthenticate(key, cancellation);
        }
        constexpr std::size_t KeySize = 32;
        constexpr std::size_t NonceSize = 24;
        constexpr std::size_t MacSize = 16;
        return std::vector<std::uint8_t>(KeySize + NonceSize + MacSize);
    }

    std::optional<tailgate::derp::DerpClient::Key> ServerKey;
    std::function<std::vector<std::uint8_t>(const tailgate::derp::DerpClient::Key&,
                                            std::stop_token)>
        OnAuthenticate;
};

} // namespace tailgate::tests::fakes::derp
