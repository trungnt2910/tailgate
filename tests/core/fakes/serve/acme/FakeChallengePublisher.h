#pragma once

#include <string>

#include <tailgate/serve/acme/Client.h>

namespace tailgate::tests::fakes
{

class FakeChallengePublisher final : public tailgate::serve::acme::ChallengePublisher
{
public:
    void PublishDnsTxt(const std::string& name, const std::string& value) override
    {
        Name = name;
        Value = value;
    }

    std::string Name;
    std::string Value;
};

} // namespace tailgate::tests::fakes
